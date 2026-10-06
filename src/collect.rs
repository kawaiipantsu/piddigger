//! Read-only collection of a process from `/proc`.
//!
//! The collector never writes to, signals or attaches to the target. Missing
//! permissions are recorded in `Snapshot::errors` instead of aborting.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::model::*;
use crate::procfs;
use crate::util;

/// Upper bounds keep a refresh cheap on processes with huge tables.
const MAX_FDS: usize = 8192;
const MAX_THREADS: usize = 4096;
const MAX_ENV_BYTES: u64 = 1 << 20;

pub struct Collector {
    pub pid: i32,
    proc_root: PathBuf,
    users: HashMap<u32, String>,
    clk_tck: u64,
    page_size: u64,
    boot_time: i64,
    init_ns: HashMap<String, String>,
    exe_cache: Option<(u64, ExeInfo)>,
    ifnames: HashMap<String, String>,
}

impl Collector {
    pub fn new(pid: i32) -> Self {
        let users = fs::read_to_string("/etc/passwd")
            .map(|s| procfs::parse_passwd(&s))
            .unwrap_or_default();
        let boot_time = fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("btime ").map(|v| v.trim().parse().ok()))
                    .flatten()
            })
            .unwrap_or(0);
        let init_ns = read_ns_links(Path::new("/proc/1"));
        Collector {
            pid,
            proc_root: PathBuf::from(format!("/proc/{pid}")),
            users,
            clk_tck: sysconf(libc::_SC_CLK_TCK).unwrap_or(100),
            page_size: sysconf(libc::_SC_PAGESIZE).unwrap_or(4096),
            boot_time,
            init_ns,
            exe_cache: None,
            ifnames: interface_names(),
        }
    }

    pub fn user_name(&self, uid: u32) -> String {
        self.users
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| uid.to_string())
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.proc_root.join(rel)
    }

    pub fn alive(&self) -> bool {
        self.proc_root.join("stat").exists()
    }

    /// Collects one complete snapshot. Volatile, fast-changing tables are read first.
    pub fn collect(&mut self) -> Snapshot {
        let started = Instant::now();
        let mut errors = Errors::default();
        let mut snap = Snapshot {
            taken_at: util::now_rfc3339(),
            host: self.host_info(),
            ..Snapshot::default()
        };

        let stat = match fs::read_to_string(self.path("stat")) {
            Ok(s) => procfs::parse_stat(&s),
            Err(e) => {
                errors.push("stat", &e);
                None
            }
        };
        let Some(stat) = stat else {
            snap.exited = !self.alive();
            snap.ident.pid = self.pid;
            snap.errors = errors.0;
            return snap;
        };
        let status = self.read_kv("status", &mut errors);

        snap.fds = self.fds(&mut errors);
        snap.sockets = self.sockets(&snap.fds, &mut errors);
        snap.threads = self.threads();
        snap.ident = self.identity(&stat, &status, &snap.host, &mut errors);
        snap.security = self.security(&status);
        snap.maps = match fs::read_to_string(self.path("maps")) {
            Ok(s) => procfs::parse_maps(&s),
            Err(e) => {
                errors.push("maps", &e);
                Vec::new()
            }
        };
        snap.mem = self.memory(&status);
        snap.namespaces = self.namespaces();
        snap.environ = self.environ(&mut errors);
        snap.limits = fs::read_to_string(self.path("limits"))
            .map(|s| procfs::parse_limits(&s))
            .unwrap_or_default();
        snap.cgroups = fs::read_to_string(self.path("cgroup"))
            .map(|s| s.lines().map(str::to_string).collect())
            .unwrap_or_default();
        snap.io = fs::read_to_string(self.path("io"))
            .map(|s| procfs::parse_io(&s))
            .unwrap_or_default();
        snap.kernel_stack = fs::read_to_string(self.path("stack"))
            .map(|s| s.lines().map(str::to_string).collect())
            .unwrap_or_default();
        snap.mount_count = fs::read_to_string(self.path("mountinfo"))
            .map(|s| s.lines().count())
            .unwrap_or(0);
        snap.ancestry = self.ancestry(stat.ppid);
        snap.children = self.children();
        snap.exe = self.exe(stat.starttime, &mut errors);

        snap.errors = errors.0;
        snap.collect_us = started.elapsed().as_micros() as u64;
        snap
    }

    fn host_info(&self) -> HostInfo {
        let uptime_secs = fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse().ok())
            .unwrap_or(0.0);
        let ld_so_preload = fs::read_to_string("/etc/ld.so.preload")
            .map(|s| {
                s.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        HostInfo {
            hostname: read_trim("/proc/sys/kernel/hostname"),
            kernel: format!(
                "{} {}",
                read_trim("/proc/sys/kernel/ostype"),
                read_trim("/proc/sys/kernel/osrelease")
            ),
            boot_time: self.boot_time,
            uptime_secs,
            clk_tck: self.clk_tck,
            page_size: self.page_size,
            num_cpus: std::thread::available_parallelism().map_or(1, |n| n.get()),
            collector_uid: unsafe { libc::geteuid() },
            ld_so_preload,
        }
    }

    fn read_kv(&self, rel: &str, errors: &mut Errors) -> HashMap<String, String> {
        match fs::read_to_string(self.path(rel)) {
            Ok(s) => procfs::parse_kv(&s),
            Err(e) => {
                errors.push(rel, &e);
                HashMap::new()
            }
        }
    }

    fn identity(
        &self,
        stat: &procfs::Stat,
        status: &HashMap<String, String>,
        host: &HostInfo,
        errors: &mut Errors,
    ) -> Identity {
        let get = |k: &str| status.get(k).cloned().unwrap_or_default();
        let uid = procfs::parse_id_quad(&get("Uid"));
        let gid = procfs::parse_id_quad(&get("Gid"));
        let start_time = self.boot_time + (stat.starttime / self.clk_tck.max(1)) as i64;
        let age_secs =
            (host.uptime_secs - stat.starttime as f64 / self.clk_tck.max(1) as f64).max(0.0);
        let link = |rel: &str, errors: &mut Errors| match fs::read_link(self.path(rel)) {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => {
                errors.push(rel, &e);
                String::new()
            }
        };
        let optional_id = |rel: &str| {
            read_trim(self.path(rel))
                .parse::<u32>()
                .ok()
                .filter(|v| *v != u32::MAX)
        };
        let tgid: i32 = get("Tgid").parse().unwrap_or(self.pid);
        Identity {
            pid: self.pid,
            ppid: stat.ppid,
            pgrp: stat.pgrp,
            session: stat.session,
            tty_nr: stat.tty_nr,
            comm: stat.comm.clone(),
            cmdline: fs::read(self.path("cmdline"))
                .map(|b| procfs::parse_nul_list(&b))
                .unwrap_or_default(),
            state: format!("{} ({})", stat.state, procfs::state_name(stat.state)),
            cwd: link("cwd", errors),
            root: link("root", errors),
            uid,
            gid,
            user: self.user_name(uid[0]),
            groups: get("Groups")
                .split_whitespace()
                .filter_map(|g| g.parse().ok())
                .collect(),
            login_uid: optional_id("loginuid"),
            audit_session: optional_id("sessionid"),
            start_time,
            age_secs,
            num_threads: stat.num_threads,
            nice: stat.nice,
            priority: stat.priority,
            processor: stat.processor,
            utime_ticks: stat.utime,
            stime_ticks: stat.stime,
            cutime_ticks: stat.cutime,
            cstime_ticks: stat.cstime,
            minflt: stat.minflt,
            majflt: stat.majflt,
            vsize: stat.vsize,
            rss_pages: stat.rss,
            wchan: read_trim(self.path("wchan")),
            oom_score: read_trim(self.path("oom_score")).parse().unwrap_or(0),
            oom_score_adj: read_trim(self.path("oom_score_adj")).parse().unwrap_or(0),
            umask: get("Umask"),
            cpus_allowed: get("Cpus_allowed_list"),
            vol_ctxt: get("voluntary_ctxt_switches").parse().unwrap_or(0),
            nonvol_ctxt: get("nonvoluntary_ctxt_switches").parse().unwrap_or(0),
            personality: read_trim(self.path("personality")),
            sched_policy: procfs::sched_policy_name(stat.policy).to_string(),
            hidden_from_listing: tgid == self.pid && !listed_in_proc(self.pid),
        }
    }

    fn security(&self, status: &HashMap<String, String>) -> Security {
        let get = |k: &str| status.get(k).cloned().unwrap_or_default();
        let caps = |k: &str| {
            let raw = get(k);
            CapSet {
                names: procfs::decode_caps(&raw),
                raw,
            }
        };
        let tracer_pid: i32 = get("TracerPid").parse().unwrap_or(0);
        let tracer_comm = (tracer_pid > 0)
            .then(|| read_trim(format!("/proc/{tracer_pid}/comm")))
            .filter(|s| !s.is_empty());
        let lsm_label = fs::read(self.path("attr/current"))
            .ok()
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .trim_matches(['\0', '\n', ' '])
                    .to_string()
            })
            .filter(|s| !s.is_empty());
        Security {
            cap_inh: caps("CapInh"),
            cap_prm: caps("CapPrm"),
            cap_eff: caps("CapEff"),
            cap_bnd: caps("CapBnd"),
            cap_amb: caps("CapAmb"),
            seccomp: match get("Seccomp").as_str() {
                "0" => "disabled".into(),
                "1" => "strict".into(),
                "2" => "filter".into(),
                "" => "unknown".into(),
                other => other.into(),
            },
            seccomp_filters: get("Seccomp_filters").parse().ok(),
            no_new_privs: get("NoNewPrivs") == "1",
            tracer_pid,
            tracer_comm,
            lsm_label,
            speculation: get("Speculation_Store_Bypass"),
        }
    }

    fn memory(&self, status: &HashMap<String, String>) -> MemSummary {
        let kb = |k: &str| status.get(k).map(|v| procfs::parse_kb(v)).unwrap_or(0);
        let rollup = fs::read_to_string(self.path("smaps_rollup"))
            .map(|s| procfs::parse_kv(&s))
            .unwrap_or_default();
        let rollup_kb = |k: &str| rollup.get(k).map(|v| procfs::parse_kb(v));
        let mem_total_kb = fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|s| {
                procfs::parse_kv(&s)
                    .get("MemTotal")
                    .map(|v| procfs::parse_kb(v))
            })
            .unwrap_or(0);
        MemSummary {
            vm_peak_kb: kb("VmPeak"),
            vm_size_kb: kb("VmSize"),
            vm_rss_kb: kb("VmRSS"),
            vm_hwm_kb: kb("VmHWM"),
            vm_swap_kb: kb("VmSwap"),
            rss_anon_kb: kb("RssAnon"),
            rss_file_kb: kb("RssFile"),
            rss_shmem_kb: kb("RssShmem"),
            vm_data_kb: kb("VmData"),
            vm_stk_kb: kb("VmStk"),
            vm_exe_kb: kb("VmExe"),
            vm_lib_kb: kb("VmLib"),
            pss_kb: rollup_kb("Pss"),
            private_dirty_kb: rollup_kb("Private_Dirty"),
            mem_total_kb,
        }
    }

    fn fds(&self, errors: &mut Errors) -> Vec<FdEntry> {
        let dir = match fs::read_dir(self.path("fd")) {
            Ok(d) => d,
            Err(e) => {
                errors.push("fd", &e);
                return Vec::new();
            }
        };
        let mut fds: Vec<i32> = dir
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .collect();
        fds.sort_unstable();
        if fds.len() > MAX_FDS {
            errors.push_msg(format!(
                "fd: {} descriptors open, showing the first {MAX_FDS}",
                fds.len()
            ));
            fds.truncate(MAX_FDS);
        }
        fds.into_iter()
            .filter_map(|fd| {
                let link = self.path(&format!("fd/{fd}"));
                let target = fs::read_link(&link).ok()?.to_string_lossy().into_owned();
                let (mut kind, deleted, inode) = procfs::classify_fd_target(&target);
                let info = fs::read_to_string(self.path(&format!("fdinfo/{fd}")))
                    .map(|s| procfs::parse_fdinfo(&s))
                    .unwrap_or_default();
                let meta = match kind {
                    FdKind::File | FdKind::Memfd | FdKind::Device => fs::metadata(&link).ok(),
                    _ => None,
                };
                if kind == FdKind::File && meta.as_ref().is_some_and(|m| m.is_dir()) {
                    kind = FdKind::Dir;
                }
                Some(FdEntry {
                    fd,
                    kind,
                    deleted,
                    pos: info.pos,
                    flags: info.flags.map(procfs::decode_open_flags),
                    mnt_id: info.mnt_id,
                    inode: inode.or(info.ino).or(meta.as_ref().map(|m| m.ino())),
                    size: meta.filter(|m| m.is_file()).map(|m| m.len()),
                    target,
                })
            })
            .collect()
    }

    fn sockets(&self, fds: &[FdEntry], errors: &mut Errors) -> Vec<SocketEntry> {
        let wanted: HashMap<u64, i32> = fds
            .iter()
            .filter(|f| f.kind == FdKind::Socket)
            .filter_map(|f| Some((f.inode?, f.fd)))
            .collect();
        if wanted.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        type SockParser = fn(&str) -> Vec<SocketEntry>;
        let tables: [(&str, SockParser); 9] = [
            ("tcp", |s| procfs::parse_net_inet(s, "tcp")),
            ("tcp6", |s| procfs::parse_net_inet(s, "tcp6")),
            ("udp", |s| procfs::parse_net_inet(s, "udp")),
            ("udp6", |s| procfs::parse_net_inet(s, "udp6")),
            ("raw", |s| procfs::parse_net_inet(s, "raw")),
            ("raw6", |s| procfs::parse_net_inet(s, "raw6")),
            ("unix", procfs::parse_net_unix),
            ("packet", procfs::parse_net_packet),
            ("netlink", procfs::parse_net_netlink),
        ];
        for (table, parse) in tables {
            let content = match fs::read_to_string(self.path(&format!("net/{table}"))) {
                Ok(c) => c,
                Err(e) => {
                    if e.kind() != io::ErrorKind::NotFound {
                        errors.push(&format!("net/{table}"), &e);
                    }
                    continue;
                }
            };
            for mut sock in parse(&content) {
                if let Some(fd) = wanted.get(&sock.inode) {
                    if !seen.insert(sock.inode) {
                        continue;
                    }
                    sock.fd = Some(*fd);
                    if sock.proto == "packet" {
                        if let Some(name) = self.ifnames.get(&sock.detail) {
                            sock.local = name.clone();
                        } else if sock.detail == "0" {
                            sock.local = "any".into();
                        }
                    }
                    out.push(sock);
                }
            }
        }
        for (inode, fd) in &wanted {
            if !seen.contains(inode) {
                out.push(SocketEntry {
                    proto: "socket".into(),
                    local: "-".into(),
                    remote: String::new(),
                    state: "OTHER".into(),
                    inode: *inode,
                    fd: Some(*fd),
                    detail: "family not exposed in /proc/net (e.g. vsock, bluetooth, alg)".into(),
                    ..SocketEntry::default()
                });
            }
        }
        out.sort_by_key(|s| (s.fd.unwrap_or(i32::MAX), s.inode));
        out
    }

    fn threads(&self) -> Vec<ThreadEntry> {
        let Ok(dir) = fs::read_dir(self.path("task")) else {
            return Vec::new();
        };
        let mut tids: Vec<i32> = dir
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .collect();
        tids.sort_unstable();
        tids.truncate(MAX_THREADS);
        tids.into_iter()
            .filter_map(|tid| {
                let base = self.path(&format!("task/{tid}"));
                let st = procfs::parse_stat(&fs::read_to_string(base.join("stat")).ok()?)?;
                Some(ThreadEntry {
                    tid,
                    comm: st.comm,
                    state: st.state.to_string(),
                    utime_ticks: st.utime,
                    stime_ticks: st.stime,
                    processor: st.processor,
                    priority: st.priority,
                    wchan: read_trim(base.join("wchan")),
                })
            })
            .collect()
    }

    fn namespaces(&self) -> Vec<NsEntry> {
        let mut ns: Vec<NsEntry> = read_ns_links(&self.proc_root)
            .into_iter()
            .map(|(name, link)| NsEntry {
                init_link: self.init_ns.get(&name).cloned(),
                name,
                link,
            })
            .collect();
        ns.sort_by(|a, b| a.name.cmp(&b.name));
        ns
    }

    fn environ(&self, errors: &mut Errors) -> Vec<EnvVar> {
        let mut buf = Vec::new();
        match fs::File::open(self.path("environ"))
            .and_then(|f| f.take(MAX_ENV_BYTES).read_to_end(&mut buf))
        {
            Ok(_) => procfs::parse_environ(&buf),
            Err(e) => {
                errors.push("environ", &e);
                Vec::new()
            }
        }
    }

    fn ancestry(&self, mut ppid: i32) -> Vec<ProcBrief> {
        let mut chain = Vec::new();
        let mut guard = HashSet::new();
        while ppid > 0 && guard.insert(ppid) && chain.len() < 64 {
            let Some(brief) = self.brief(ppid) else { break };
            ppid = brief.ppid;
            chain.push(brief);
        }
        chain
    }

    fn children(&self) -> Vec<ProcBrief> {
        let mut pids: Vec<i32> = Vec::new();
        let mut have_children_file = false;
        if let Ok(dir) = fs::read_dir(self.path("task")) {
            for task in dir.flatten() {
                if let Ok(s) = fs::read_to_string(task.path().join("children")) {
                    have_children_file = true;
                    pids.extend(s.split_whitespace().filter_map(|p| p.parse::<i32>().ok()));
                }
            }
        }
        if !have_children_file {
            pids = all_pids()
                .into_iter()
                .filter(|p| {
                    fs::read_to_string(format!("/proc/{p}/stat"))
                        .ok()
                        .and_then(|s| procfs::parse_stat(&s))
                        .is_some_and(|st| st.ppid == self.pid)
                })
                .collect();
        }
        pids.sort_unstable();
        pids.dedup();
        pids.into_iter().filter_map(|p| self.brief(p)).collect()
    }

    pub fn brief(&self, pid: i32) -> Option<ProcBrief> {
        let st = procfs::parse_stat(&fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)?;
        let uid = fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|s| {
                procfs::parse_kv(&s)
                    .get("Uid")
                    .map(|u| procfs::parse_id_quad(u)[0])
            })
            .unwrap_or(0);
        let mut cmdline = fs::read(format!("/proc/{pid}/cmdline"))
            .map(|b| procfs::parse_nul_list(&b).join(" "))
            .unwrap_or_default();
        util::truncate_in_place(&mut cmdline, 240);
        Some(ProcBrief {
            pid,
            ppid: st.ppid,
            comm: st.comm,
            user: self.user_name(uid),
            cmdline,
            exe_deleted: fs::read_link(format!("/proc/{pid}/exe"))
                .is_ok_and(|p| p.to_string_lossy().ends_with(" (deleted)")),
        })
    }

    /// Executable metadata and SHA-256. Hashing reads through `/proc/<pid>/exe`,
    /// which still works when the file was deleted. Cached per process start time.
    fn exe(&mut self, starttime: u64, errors: &mut Errors) -> ExeInfo {
        if let Some((cached_start, info)) = &self.exe_cache {
            if *cached_start == starttime {
                return info.clone();
            }
        }
        let link = self.path("exe");
        let path = match fs::read_link(&link) {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => {
                errors.push("exe", &e);
                return ExeInfo::default();
            }
        };
        let mut info = ExeInfo {
            deleted: path.ends_with(" (deleted)"),
            memfd: path.starts_with("/memfd:"),
            path,
            ..ExeInfo::default()
        };
        if let Ok(meta) = fs::metadata(&link) {
            info.size = Some(meta.len());
            info.mode = Some(format!("{:o}", meta.mode() & 0o7777));
            info.owner = Some(format!("{}:{}", self.user_name(meta.uid()), meta.gid()));
            info.inode = Some(meta.ino());
            info.mtime = meta.modified().ok().map(util::system_time_rfc3339);
            info.atime = meta.accessed().ok().map(util::system_time_rfc3339);
            info.ctime = Some(util::unix_rfc3339(meta.ctime(), meta.ctime_nsec() as u32));
            info.btime = meta.created().ok().map(util::system_time_rfc3339);
        }
        match hash_file(&link) {
            Ok((hash, header)) => {
                info.sha256 = Some(hash);
                info.elf = procfs::describe_elf(&header);
            }
            Err(e) => errors.push("exe (hash)", &e),
        }
        self.exe_cache = Some((starttime, info.clone()));
        info
    }

    /// Lightweight listing of every visible process for the picker.
    pub fn list_processes(&self) -> Vec<ProcRow> {
        all_pids()
            .into_iter()
            .filter_map(|pid| {
                let st =
                    procfs::parse_stat(&fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)?;
                let status = fs::read_to_string(format!("/proc/{pid}/status"))
                    .map(|s| procfs::parse_kv(&s))
                    .unwrap_or_default();
                let uid = status
                    .get("Uid")
                    .map(|u| procfs::parse_id_quad(u)[0])
                    .unwrap_or(0);
                let cmd = fs::read(format!("/proc/{pid}/cmdline"))
                    .map(|b| procfs::parse_nul_list(&b).join(" "))
                    .unwrap_or_default();
                let kernel_thread = cmd.is_empty() && (st.ppid == 2 || pid == 2);
                Some(ProcRow {
                    pid,
                    ppid: st.ppid,
                    user: self.user_name(uid),
                    state: st.state.to_string(),
                    rss_kb: st.rss * self.page_size / 1024,
                    threads: st.num_threads,
                    cmdline: if cmd.is_empty() {
                        format!("[{}]", st.comm)
                    } else {
                        cmd
                    },
                    comm: st.comm,
                    exe_deleted: fs::read_link(format!("/proc/{pid}/exe"))
                        .is_ok_and(|p| p.to_string_lossy().ends_with(" (deleted)")),
                    kernel_thread,
                })
            })
            .collect()
    }
}

/// Collects error messages without repeating the same failure every refresh.
#[derive(Default)]
struct Errors(Vec<String>);

impl Errors {
    fn push(&mut self, what: &str, e: &io::Error) {
        let msg = match e.kind() {
            io::ErrorKind::PermissionDenied => {
                format!("{what}: permission denied (need root or CAP_SYS_PTRACE)")
            }
            io::ErrorKind::NotFound => format!("{what}: not available"),
            _ => format!("{what}: {e}"),
        };
        self.push_msg(msg);
    }
    fn push_msg(&mut self, msg: String) {
        if !self.0.contains(&msg) {
            self.0.push(msg);
        }
    }
}

fn read_ns_links(proc_dir: &Path) -> HashMap<String, String> {
    let Ok(dir) = fs::read_dir(proc_dir.join("ns")) else {
        return HashMap::new();
    };
    dir.flatten()
        .filter_map(|e| {
            let link = fs::read_link(e.path()).ok()?;
            Some((
                e.file_name().to_string_lossy().into_owned(),
                link.to_string_lossy().into_owned(),
            ))
        })
        .collect()
}

pub fn all_pids() -> Vec<i32> {
    let mut pids: Vec<i32> = fs::read_dir("/proc")
        .map(|d| {
            d.flatten()
                .filter_map(|e| e.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    pids.sort_unstable();
    pids
}

fn listed_in_proc(pid: i32) -> bool {
    all_pids().binary_search(&pid).is_ok()
}

fn interface_names() -> HashMap<String, String> {
    let Ok(dir) = fs::read_dir("/sys/class/net") else {
        return HashMap::new();
    };
    dir.flatten()
        .filter_map(|e| {
            let idx = read_trim(e.path().join("ifindex"));
            Some((idx, e.file_name().to_str()?.to_string()))
        })
        .collect()
}

fn read_trim(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn sysconf(name: libc::c_int) -> Option<u64> {
    let v = unsafe { libc::sysconf(name) };
    (v > 0).then_some(v as u64)
}

/// Streams a file through SHA-256 and returns the digest plus its first bytes.
pub fn hash_file(path: &Path) -> io::Result<(String, Vec<u8>)> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut header = Vec::new();
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if header.len() < 64 {
            header.extend_from_slice(&buf[..n.min(64 - header.len())]);
        }
        hasher.update(&buf[..n]);
    }
    Ok((util::hex(&hasher.finalize()), header))
}

/// True when the process is a kernel thread or otherwise unreadable.
pub fn pid_exists(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}/stat")).exists()
}

/// Seconds since the UNIX epoch, used for activity timestamps.
pub fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_own_process() {
        let me = std::process::id() as i32;
        let mut c = Collector::new(me);
        let snap = c.collect();
        assert_eq!(snap.ident.pid, me);
        assert!(!snap.exited);
        assert!(!snap.ident.comm.is_empty());
        assert!(!snap.maps.is_empty(), "own maps must be readable");
        assert!(snap.fds.iter().any(|f| f.fd == 0 || f.fd == 1 || f.fd == 2));
        assert!(snap.exe.sha256.as_deref().is_some_and(|h| h.len() == 64));
        assert!(!snap.threads.is_empty());
        assert!(!snap.ident.hidden_from_listing);
    }

    #[test]
    fn sees_own_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut c = Collector::new(std::process::id() as i32);
        let snap = c.collect();
        assert!(
            snap.sockets
                .iter()
                .any(|s| s.state == "LISTEN" && s.local == format!("127.0.0.1:{port}")),
            "{:?}",
            snap.sockets
        );
    }

    #[test]
    fn missing_pid_is_exited() {
        let mut c = Collector::new(i32::MAX - 7);
        let snap = c.collect();
        assert!(snap.exited);
    }
}
