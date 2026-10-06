//! Plain data model for one point-in-time view of a process.
//!
//! Collectors fill these structures from `/proc`; the UI, the findings engine
//! and the evidence writer only ever consume them. Everything is serialisable
//! so a snapshot can be preserved verbatim as `report.json`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    /// RFC 3339 UTC timestamp of when collection started.
    pub taken_at: String,
    /// Wall-clock duration of the collection pass in microseconds.
    pub collect_us: u64,
    pub host: HostInfo,
    pub ident: Identity,
    pub exe: ExeInfo,
    pub ancestry: Vec<ProcBrief>,
    pub children: Vec<ProcBrief>,
    pub fds: Vec<FdEntry>,
    pub sockets: Vec<SocketEntry>,
    pub maps: Vec<MapEntry>,
    pub mem: MemSummary,
    pub namespaces: Vec<NsEntry>,
    pub security: Security,
    pub threads: Vec<ThreadEntry>,
    pub environ: Vec<EnvVar>,
    pub limits: Vec<LimitEntry>,
    pub cgroups: Vec<String>,
    pub io: IoStats,
    pub kernel_stack: Vec<String>,
    pub mount_count: usize,
    /// Non-fatal collection problems (permission denied, races, ...).
    pub errors: Vec<String>,
    /// True once the target vanished between refreshes.
    pub exited: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub kernel: String,
    pub boot_time: i64,
    pub uptime_secs: f64,
    pub clk_tck: u64,
    pub page_size: u64,
    pub num_cpus: usize,
    pub collector_uid: u32,
    pub ld_so_preload: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Identity {
    pub pid: i32,
    pub ppid: i32,
    pub pgrp: i32,
    pub session: i32,
    pub tty_nr: i32,
    pub comm: String,
    pub cmdline: Vec<String>,
    pub state: String,
    pub cwd: String,
    pub root: String,
    pub uid: [u32; 4],
    pub gid: [u32; 4],
    pub user: String,
    pub groups: Vec<u32>,
    pub login_uid: Option<u32>,
    pub audit_session: Option<u32>,
    /// Process start as UNIX seconds (boot time + starttime / CLK_TCK).
    pub start_time: i64,
    pub age_secs: f64,
    pub num_threads: i64,
    pub nice: i64,
    pub priority: i64,
    pub processor: i64,
    pub utime_ticks: u64,
    pub stime_ticks: u64,
    pub cutime_ticks: u64,
    pub cstime_ticks: u64,
    pub minflt: u64,
    pub majflt: u64,
    pub vsize: u64,
    pub rss_pages: u64,
    pub wchan: String,
    pub oom_score: i64,
    pub oom_score_adj: i64,
    pub umask: String,
    pub cpus_allowed: String,
    pub vol_ctxt: u64,
    pub nonvol_ctxt: u64,
    pub personality: String,
    pub sched_policy: String,
    /// True when the PID is reachable but missing from the `/proc` listing.
    pub hidden_from_listing: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExeInfo {
    pub path: String,
    pub deleted: bool,
    pub memfd: bool,
    pub sha256: Option<String>,
    pub size: Option<u64>,
    pub mode: Option<String>,
    pub owner: Option<String>,
    pub inode: Option<u64>,
    pub mtime: Option<String>,
    pub atime: Option<String>,
    pub ctime: Option<String>,
    pub btime: Option<String>,
    pub elf: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProcBrief {
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    pub user: String,
    pub cmdline: String,
    pub exe_deleted: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum FdKind {
    #[default]
    File,
    Dir,
    Socket,
    Pipe,
    AnonInode,
    Memfd,
    Device,
    Other,
}

impl FdKind {
    pub fn label(self) -> &'static str {
        match self {
            FdKind::File => "file",
            FdKind::Dir => "dir",
            FdKind::Socket => "socket",
            FdKind::Pipe => "pipe",
            FdKind::AnonInode => "anon",
            FdKind::Memfd => "memfd",
            FdKind::Device => "device",
            FdKind::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct FdEntry {
    pub fd: i32,
    pub target: String,
    pub kind: FdKind,
    pub deleted: bool,
    pub pos: Option<u64>,
    pub flags: Option<String>,
    pub mnt_id: Option<u64>,
    pub inode: Option<u64>,
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SocketEntry {
    pub proto: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub inode: u64,
    pub fd: Option<i32>,
    pub uid: Option<u32>,
    pub tx_queue: u64,
    pub rx_queue: u64,
    /// Unix socket path or packet socket interface, when applicable.
    pub detail: String,
}

impl SocketEntry {
    pub fn is_listening(&self) -> bool {
        self.state == "LISTEN" || (self.proto.starts_with("udp") && self.remote_is_unspecified())
    }

    pub fn remote_is_unspecified(&self) -> bool {
        self.remote.is_empty()
            || self.remote.starts_with("0.0.0.0:")
            || self.remote.starts_with("[::]:")
            || self.remote == "*"
    }

    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.proto, self.local, self.remote, self.inode
        )
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum MapKind {
    #[default]
    Anon,
    File,
    Heap,
    Stack,
    Vdso,
    Memfd,
    Deleted,
    Special,
}

impl MapKind {
    pub fn label(self) -> &'static str {
        match self {
            MapKind::Anon => "anon",
            MapKind::File => "file",
            MapKind::Heap => "heap",
            MapKind::Stack => "stack",
            MapKind::Vdso => "vdso",
            MapKind::Memfd => "memfd",
            MapKind::Deleted => "deleted",
            MapKind::Special => "special",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MapEntry {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub offset: u64,
    pub dev: String,
    pub inode: u64,
    pub path: String,
    pub kind: MapKind,
}

impl MapEntry {
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
    pub fn writable(&self) -> bool {
        self.perms.as_bytes().get(1) == Some(&b'w')
    }
    pub fn executable(&self) -> bool {
        self.perms.as_bytes().get(2) == Some(&b'x')
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemSummary {
    pub vm_peak_kb: u64,
    pub vm_size_kb: u64,
    pub vm_rss_kb: u64,
    pub vm_hwm_kb: u64,
    pub vm_swap_kb: u64,
    pub rss_anon_kb: u64,
    pub rss_file_kb: u64,
    pub rss_shmem_kb: u64,
    pub vm_data_kb: u64,
    pub vm_stk_kb: u64,
    pub vm_exe_kb: u64,
    pub vm_lib_kb: u64,
    pub pss_kb: Option<u64>,
    pub private_dirty_kb: Option<u64>,
    pub mem_total_kb: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NsEntry {
    pub name: String,
    pub link: String,
    pub init_link: Option<String>,
}

impl NsEntry {
    pub fn differs_from_init(&self) -> bool {
        matches!(&self.init_link, Some(init) if init != &self.link)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapSet {
    pub raw: String,
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Security {
    pub cap_inh: CapSet,
    pub cap_prm: CapSet,
    pub cap_eff: CapSet,
    pub cap_bnd: CapSet,
    pub cap_amb: CapSet,
    pub seccomp: String,
    pub seccomp_filters: Option<u32>,
    pub no_new_privs: bool,
    pub tracer_pid: i32,
    pub tracer_comm: Option<String>,
    pub lsm_label: Option<String>,
    pub speculation: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ThreadEntry {
    pub tid: i32,
    pub comm: String,
    pub state: String,
    pub utime_ticks: u64,
    pub stime_ticks: u64,
    pub processor: i64,
    pub priority: i64,
    pub wchan: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LimitEntry {
    pub name: String,
    pub soft: String,
    pub hard: String,
    pub unit: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IoStats {
    pub rchar: u64,
    pub wchar: u64,
    pub syscr: u64,
    pub syscw: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub cancelled_write_bytes: u64,
    pub available: bool,
}

/// One row in the process picker.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcRow {
    pub pid: i32,
    pub ppid: i32,
    pub user: String,
    pub comm: String,
    pub state: String,
    pub rss_kb: u64,
    pub threads: i64,
    pub cmdline: String,
    pub exe_deleted: bool,
    pub kernel_thread: bool,
}
