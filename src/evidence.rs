//! Evidence case folder: write-once artifacts, SHA-256 manifest and an
//! append-only chain-of-custody log.
//!
//! Layout of a case:
//!
//! ```text
//! piddigger-case-<host>-<pid>-<UTC>/
//!   case.json            case metadata, collector identity and tool hash
//!   custody.log          append-only, timestamped action log
//!   SHA256SUMS           manifest of every artifact (sha256sum -c compatible)
//!   snap-001-<UTC>/      one directory per snapshot (raw /proc copies, report.json, ...)
//!   trace/               output of strace, perf, bpftrace, tcpdump, gdb
//!   memory/              gcore memory images
//! ```

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::activity::Event;
use crate::collect;
use crate::findings::Finding;
use crate::model::{FdKind, Snapshot};
use crate::util;

#[derive(Debug, Clone, Serialize)]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub collected_at: String,
    pub note: String,
}

#[derive(Debug, Clone, Copy)]
pub struct PreserveOptions {
    pub copy_exe: bool,
    pub max_copy_bytes: u64,
}

impl Default for PreserveOptions {
    fn default() -> Self {
        PreserveOptions {
            copy_exe: true,
            max_copy_bytes: 512 << 20,
        }
    }
}

#[derive(Debug, Default)]
pub struct PreserveSummary {
    pub dir: String,
    pub files: usize,
    pub bytes: u64,
    pub skipped: Vec<String>,
}

pub struct Case {
    pub dir: PathBuf,
    pub id: String,
    pub created: String,
    started: Instant,
    pub entries: Vec<ManifestEntry>,
    pub log_tail: Vec<String>,
    snap_seq: u32,
}

/// `/proc/<pid>` files copied verbatim, ordered from most to least volatile.
const PROC_FILES: &[&str] = &[
    "stat",
    "status",
    "wchan",
    "stack",
    "syscall",
    "sched",
    "schedstat",
    "io",
    "net/tcp",
    "net/tcp6",
    "net/udp",
    "net/udp6",
    "net/raw",
    "net/raw6",
    "net/unix",
    "net/packet",
    "net/netlink",
    "maps",
    "smaps",
    "smaps_rollup",
    "timers",
    "cmdline",
    "comm",
    "environ",
    "cgroup",
    "mountinfo",
    "limits",
    "loginuid",
    "sessionid",
    "attr/current",
    "oom_score",
    "oom_score_adj",
    "personality",
    "coredump_filter",
    "uid_map",
    "gid_map",
    "setgroups",
];

fn sanitize(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cleaned = cleaned.trim_start_matches('.').to_string();
    if cleaned.is_empty() {
        "unnamed".into()
    } else {
        util::truncate(&cleaned, 80).replace('…', "")
    }
}

fn mkdir_private(path: &Path) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(path)
}

impl Case {
    /// Creates a new case directory below `root`. Never reuses an existing one.
    pub fn open(root: &Path, snap: &Snapshot) -> io::Result<Case> {
        let id = format!(
            "piddigger-case-{}-{}-{}",
            sanitize(&snap.host.hostname),
            snap.ident.pid,
            util::now_compact()
        );
        mkdir_private(root)?;
        let dir = root.join(&id);
        DirBuilder::new().mode(0o700).create(&dir)?;
        let mut case = Case {
            dir: fs::canonicalize(&dir).unwrap_or(dir),
            id,
            created: util::now_rfc3339(),
            started: Instant::now(),
            entries: Vec::new(),
            log_tail: Vec::new(),
            snap_seq: 0,
        };
        let tool_hash = collect::hash_file(Path::new("/proc/self/exe"))
            .map(|(h, _)| h)
            .unwrap_or_default();
        let euid = unsafe { libc::geteuid() };
        let meta = serde_json::json!({
            "case_id": case.id,
            "created": case.created,
            "tool": {
                "name": env!("CARGO_PKG_NAME"),
                "version": env!("CARGO_PKG_VERSION"),
                "sha256": tool_hash,
                "argv": std::env::args().collect::<Vec<_>>(),
            },
            "collector": { "euid": euid, "pid": std::process::id() },
            "host": snap.host,
            "target": {
                "pid": snap.ident.pid,
                "comm": snap.ident.comm,
                "cmdline": snap.ident.cmdline,
                "start_time": util::unix_rfc3339(snap.ident.start_time, 0),
                "exe": snap.exe.path,
                "exe_sha256": snap.exe.sha256,
            },
            "notes": "Times are UTC. Artifacts are write-once (mode 0400); verify with: sha256sum -c SHA256SUMS",
        });
        case.log(
            "OPEN",
            &format!(
                "case {} target pid={} comm={} by euid={euid} tool={} {}",
                case.id,
                snap.ident.pid,
                snap.ident.comm,
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            ),
        );
        let json = serde_json::to_vec_pretty(&meta).unwrap_or_default();
        case.write_file("case.json", &json, "case metadata")?;
        Ok(case)
    }

    pub fn elapsed(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    /// Appends one line to the custody log. Failures are reported in the tail.
    pub fn log(&mut self, action: &str, detail: &str) {
        let line = format!(
            "{} +{:>10.3}s {:<10} {}",
            util::now_rfc3339(),
            self.elapsed(),
            action,
            detail.replace('\n', " ")
        );
        let written = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(self.dir.join("custody.log"))
            .and_then(|mut f| writeln!(f, "{line}").and_then(|_| f.sync_data()));
        if let Err(e) = written {
            self.log_tail
                .push(format!("!! custody log write failed: {e}"));
        }
        self.log_tail.push(line);
        if self.log_tail.len() > 400 {
            self.log_tail.drain(..100);
        }
    }

    fn create_new(&self, rel: &str) -> io::Result<(PathBuf, fs::File)> {
        let path = self.dir.join(rel);
        if let Some(parent) = path.parent() {
            mkdir_private(parent)?;
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        Ok((path, file))
    }

    fn seal(
        &mut self,
        rel: &str,
        path: &Path,
        size: u64,
        sha256: String,
        note: &str,
    ) -> ManifestEntry {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o400));
        let entry = ManifestEntry {
            path: rel.to_string(),
            size,
            sha256,
            collected_at: util::now_rfc3339(),
            note: note.to_string(),
        };
        self.log(
            "COLLECT",
            &format!("{rel} size={size} sha256={} ({note})", entry.sha256),
        );
        self.entries.push(entry.clone());
        let _ = self.write_manifest();
        entry
    }

    /// Writes a new artifact. Existing files are never overwritten.
    pub fn write_file(&mut self, rel: &str, data: &[u8], note: &str) -> io::Result<ManifestEntry> {
        let (path, mut file) = self.create_new(rel)?;
        file.write_all(data)?;
        file.sync_all()?;
        let hash = util::hex(&Sha256::digest(data));
        Ok(self.seal(rel, &path, data.len() as u64, hash, note))
    }

    /// Streams `src` into the case while hashing. Returns whether it was truncated.
    pub fn copy_from(
        &mut self,
        rel: &str,
        src: &Path,
        max: u64,
        note: &str,
    ) -> io::Result<(ManifestEntry, bool)> {
        let mut input = fs::File::open(src)?;
        let (path, mut out) = self.create_new(rel)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut total = 0u64;
        let mut truncated = false;
        loop {
            let n = input.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let take = (n as u64).min(max - total) as usize;
            out.write_all(&buf[..take])?;
            hasher.update(&buf[..take]);
            total += take as u64;
            if total >= max {
                truncated = input.read(&mut buf[..1])? > 0;
                break;
            }
        }
        out.sync_all()?;
        let note = if truncated {
            format!("{note}; TRUNCATED at {max} bytes")
        } else {
            note.to_string()
        };
        let entry = self.seal(rel, &path, total, util::hex(&hasher.finalize()), &note);
        Ok((entry, truncated))
    }

    /// Hashes and seals a file that an external tool wrote inside the case.
    pub fn register(&mut self, path: &Path, note: &str) -> io::Result<ManifestEntry> {
        let rel = path
            .strip_prefix(&self.dir)
            .map(|p| p.to_string_lossy().into_owned())
            .map_err(|_| io::Error::other("artifact outside case directory"))?;
        let (hash, _) = collect::hash_file(path)?;
        let size = fs::metadata(path)?.len();
        Ok(self.seal(&rel, path, size, hash, note))
    }

    /// Rewrites `SHA256SUMS` atomically.
    pub fn write_manifest(&self) -> io::Result<()> {
        let mut body = String::new();
        for e in &self.entries {
            body.push_str(&format!("{}  {}\n", e.sha256, e.path));
        }
        let tmp = self.dir.join(".SHA256SUMS.tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(tmp, self.dir.join("SHA256SUMS"))
    }

    /// Re-hashes every artifact and reports mismatches.
    pub fn verify(&mut self) -> Vec<(String, Result<bool, String>)> {
        let results: Vec<_> = self
            .entries
            .iter()
            .map(|e| {
                let r = collect::hash_file(&self.dir.join(&e.path))
                    .map(|(h, _)| h == e.sha256)
                    .map_err(|err| err.to_string());
                (e.path.clone(), r)
            })
            .collect();
        let bad = results
            .iter()
            .filter(|(_, r)| !matches!(r, Ok(true)))
            .count();
        self.log(
            "VERIFY",
            &format!("{} artifacts, {bad} failed", results.len()),
        );
        results
    }

    pub fn subdir(&self, name: &str) -> io::Result<PathBuf> {
        let p = self.dir.join(name);
        mkdir_private(&p)?;
        Ok(p)
    }

    pub fn close(&mut self) {
        let _ = self.write_manifest();
        let manifest_hash = collect::hash_file(&self.dir.join("SHA256SUMS"))
            .map(|(h, _)| h)
            .unwrap_or_default();
        self.log(
            "CLOSE",
            &format!(
                "{} artifacts, SHA256SUMS sha256={manifest_hash}",
                self.entries.len()
            ),
        );
    }

    /// Preserves a full snapshot: raw `/proc` copies first, then derived
    /// reports, the executable and deleted-but-open files.
    pub fn preserve(
        &mut self,
        snap: &Snapshot,
        findings: &[Finding],
        activity: &[Event],
        opts: PreserveOptions,
    ) -> io::Result<PreserveSummary> {
        self.snap_seq += 1;
        let prefix = format!("snap-{:03}-{}", self.snap_seq, util::now_compact());
        let pid = snap.ident.pid;
        let proc_dir = PathBuf::from(format!("/proc/{pid}"));
        let mut sum = PreserveSummary {
            dir: prefix.clone(),
            ..PreserveSummary::default()
        };
        self.log("SNAPSHOT", &format!("begin {prefix} pid={pid}"));
        let record = |sum: &mut PreserveSummary, r: io::Result<ManifestEntry>, what: &str| match r {
            Ok(e) => {
                sum.files += 1;
                sum.bytes += e.size;
            }
            Err(e) => sum.skipped.push(format!("{what}: {e}")),
        };

        // 1. Raw /proc copies, most volatile first.
        for rel in PROC_FILES {
            match read_capped(&proc_dir.join(rel), 256 << 20) {
                Ok(data) => {
                    let r = self.write_file(
                        &format!("{prefix}/proc/{}", rel.replace('/', "_")),
                        &data,
                        &format!("/proc/{pid}/{rel}"),
                    );
                    record(&mut sum, r, rel);
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => sum.skipped.push(format!("{rel}: {e}")),
            }
        }
        let fd_listing: String = snap
            .fds
            .iter()
            .map(|f| {
                format!(
                    "{}\t{}\t{}\tpos={}\tflags={}\n",
                    f.fd,
                    f.kind.label(),
                    f.target,
                    f.pos.map_or("-".into(), |p| p.to_string()),
                    f.flags.clone().unwrap_or_default()
                )
            })
            .collect();
        let r = self.write_file(
            &format!("{prefix}/proc/fd.txt"),
            fd_listing.as_bytes(),
            "descriptor table",
        );
        record(&mut sum, r, "fd.txt");
        let ns: String = snap
            .namespaces
            .iter()
            .map(|n| {
                format!(
                    "{}\t{}\tinit={}\n",
                    n.name,
                    n.link,
                    n.init_link.clone().unwrap_or_else(|| "?".into())
                )
            })
            .collect();
        let r = self.write_file(
            &format!("{prefix}/proc/ns.txt"),
            ns.as_bytes(),
            "namespace links",
        );
        record(&mut sum, r, "ns.txt");
        let tasks: String = snap
            .threads
            .iter()
            .map(|t| {
                format!(
                    "{}\t{}\t{}\tutime={}\tstime={}\twchan={}\n",
                    t.tid, t.comm, t.state, t.utime_ticks, t.stime_ticks, t.wchan
                )
            })
            .collect();
        let r = self.write_file(
            &format!("{prefix}/proc/task.txt"),
            tasks.as_bytes(),
            "thread table",
        );
        record(&mut sum, r, "task.txt");

        // 2. Derived, human and machine readable reports.
        let report = serde_json::to_vec_pretty(snap).unwrap_or_default();
        let r = self.write_file(
            &format!("{prefix}/report.json"),
            &report,
            "full parsed snapshot",
        );
        record(&mut sum, r, "report.json");
        let r = self.write_file(
            &format!("{prefix}/findings.json"),
            &serde_json::to_vec_pretty(findings).unwrap_or_default(),
            "triage findings",
        );
        record(&mut sum, r, "findings.json");
        let r = self.write_file(
            &format!("{prefix}/findings.txt"),
            findings_text(snap, findings).as_bytes(),
            "triage findings (text)",
        );
        record(&mut sum, r, "findings.txt");
        let events: String = activity
            .iter()
            .filter_map(|e| serde_json::to_string(e).ok())
            .map(|l| l + "\n")
            .collect();
        let r = self.write_file(
            &format!("{prefix}/activity.jsonl"),
            events.as_bytes(),
            "observed activity timeline",
        );
        record(&mut sum, r, "activity.jsonl");
        if !snap.host.ld_so_preload.is_empty() {
            if let Ok(data) = fs::read("/etc/ld.so.preload") {
                let r = self.write_file(
                    &format!("{prefix}/host/ld.so.preload"),
                    &data,
                    "/etc/ld.so.preload",
                );
                record(&mut sum, r, "ld.so.preload");
            }
        }

        // 3. Executable, read through the magic link so deleted binaries survive.
        if opts.copy_exe && !snap.exe.path.is_empty() {
            let name = sanitize(
                snap.exe
                    .path
                    .rsplit('/')
                    .next()
                    .unwrap_or("exe")
                    .trim_end_matches(" (deleted)"),
            );
            match self.copy_from(
                &format!("{prefix}/exe/{name}.bin"),
                &proc_dir.join("exe"),
                opts.max_copy_bytes,
                &format!("copy of /proc/{pid}/exe → {}", snap.exe.path),
            ) {
                Ok((entry, _)) => {
                    if let Some(expected) = &snap.exe.sha256 {
                        if expected != &entry.sha256 {
                            self.log(
                                "WARN",
                                &format!(
                                    "exe hash changed since live view: {expected} → {}",
                                    entry.sha256
                                ),
                            );
                        }
                    }
                    sum.files += 1;
                    sum.bytes += entry.size;
                }
                Err(e) => sum.skipped.push(format!("exe: {e}")),
            }
        }

        // 4. Deleted-but-open and memfd files.
        for f in snap
            .fds
            .iter()
            .filter(|f| f.deleted && matches!(f.kind, FdKind::File | FdKind::Memfd))
        {
            let name = sanitize(
                f.target
                    .rsplit('/')
                    .next()
                    .unwrap_or("file")
                    .trim_end_matches(" (deleted)"),
            );
            match self.copy_from(
                &format!("{prefix}/recovered/fd-{}-{name}", f.fd),
                &proc_dir.join(format!("fd/{}", f.fd)),
                opts.max_copy_bytes,
                &format!("recovered deleted-but-open fd {} → {}", f.fd, f.target),
            ) {
                Ok((entry, _)) => {
                    sum.files += 1;
                    sum.bytes += entry.size;
                }
                Err(e) => sum.skipped.push(format!("fd {}: {e}", f.fd)),
            }
        }

        self.log(
            "SNAPSHOT",
            &format!(
                "end {prefix}: {} files, {} bytes, {} skipped",
                sum.files,
                sum.bytes,
                sum.skipped.len()
            ),
        );
        Ok(sum)
    }

    /// Copies one descriptor's content (e.g. a deleted file) into the case.
    pub fn recover_fd(
        &mut self,
        pid: i32,
        fd: i32,
        target: &str,
        max: u64,
    ) -> io::Result<(ManifestEntry, bool)> {
        let name = sanitize(
            target
                .rsplit('/')
                .next()
                .unwrap_or("file")
                .trim_end_matches(" (deleted)"),
        );
        self.copy_from(
            &format!("recovered/fd-{fd}-{}-{name}", util::now_compact()),
            Path::new(&format!("/proc/{pid}/fd/{fd}")),
            max,
            &format!("recovered fd {fd} → {target}"),
        )
    }
}

fn read_capped(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    fs::File::open(path)?.take(max).read_to_end(&mut buf)?;
    Ok(buf)
}

pub fn findings_text(snap: &Snapshot, findings: &[Finding]) -> String {
    let mut out = format!(
        "piddigger {} triage report\nhost: {} ({})\ntarget: pid {} '{}' {}\nexe: {} sha256={}\ncollected: {}\n\n",
        env!("CARGO_PKG_VERSION"),
        snap.host.hostname,
        snap.host.kernel,
        snap.ident.pid,
        snap.ident.comm,
        snap.ident.cmdline.join(" "),
        snap.exe.path,
        snap.exe.sha256.clone().unwrap_or_else(|| "unavailable".into()),
        snap.taken_at,
    );
    if findings.is_empty() {
        out.push_str("No findings.\n");
    }
    for f in findings {
        out.push_str(&format!(
            "[{}] ({}) {}\n  why: {}\n  evidence: {}\n  next: {}\n\n",
            f.severity.label(),
            f.category,
            f.title,
            f.detail,
            f.evidence,
            f.advice
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{collect::Collector, findings};

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "piddigger-test-{}-{}",
            std::process::id(),
            util::now_compact()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn case_roundtrip_and_verify() {
        let root = scratch();
        let mut c = Collector::new(std::process::id() as i32);
        let snap = c.collect();
        let f = findings::analyze(&snap);
        let mut case = Case::open(&root, &snap).unwrap();
        let sum = case
            .preserve(
                &snap,
                &f,
                &[],
                PreserveOptions {
                    copy_exe: true,
                    max_copy_bytes: 1 << 20,
                },
            )
            .unwrap();
        assert!(sum.files > 10, "{sum:?}");
        assert!(case.dir.join("SHA256SUMS").exists());
        assert!(case.verify().iter().all(|(_, r)| matches!(r, Ok(true))));
        // Artifacts are sealed read-only and never overwritten.
        assert!(case.write_file("case.json", b"x", "dup").is_err());
        case.close();
        let log = fs::read_to_string(case.dir.join("custody.log")).unwrap();
        assert!(log.contains("OPEN") && log.contains("SNAPSHOT") && log.contains("CLOSE"));
        let _ = fs::set_permissions(&root, fs::Permissions::from_mode(0o700));
        let _ = std::process::Command::new("chmod")
            .args(["-R", "u+w"])
            .arg(&root)
            .status();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sanitize_names() {
        assert_eq!(sanitize("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(sanitize(".hidden"), "hidden");
        assert_eq!(sanitize(""), "unnamed");
    }
}
