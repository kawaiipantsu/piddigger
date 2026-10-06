//! Pure parsers for the textual formats exposed by Linux `/proc`.
//!
//! Nothing in here touches the filesystem, which keeps every format testable
//! against captured samples.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::model::{EnvVar, FdKind, IoStats, LimitEntry, MapEntry, MapKind, SocketEntry};

/// Fields of `/proc/<pid>/stat` that piddigger uses.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Stat {
    pub pid: i32,
    pub comm: String,
    pub state: char,
    pub ppid: i32,
    pub pgrp: i32,
    pub session: i32,
    pub tty_nr: i32,
    pub minflt: u64,
    pub majflt: u64,
    pub utime: u64,
    pub stime: u64,
    pub cutime: u64,
    pub cstime: u64,
    pub priority: i64,
    pub nice: i64,
    pub num_threads: i64,
    pub starttime: u64,
    pub vsize: u64,
    pub rss: u64,
    pub processor: i64,
    pub policy: u32,
}

/// Parses `/proc/<pid>/stat`. The command name is wrapped in parentheses and
/// may itself contain spaces or parentheses, so it is located by the last `)`.
pub fn parse_stat(content: &str) -> Option<Stat> {
    let open = content.find('(')?;
    let close = content.rfind(')')?;
    if close < open {
        return None;
    }
    let pid = content[..open].trim().parse().ok()?;
    let comm = content[open + 1..close].to_string();
    let rest: Vec<&str> = content[close + 1..].split_whitespace().collect();
    // rest[0] is field 3 (state); field N lives at rest[N - 3].
    let field = |n: usize| rest.get(n - 3).copied().unwrap_or("0");
    let num = |n: usize| field(n).parse::<u64>().unwrap_or(0);
    let signed = |n: usize| field(n).parse::<i64>().unwrap_or(0);
    Some(Stat {
        pid,
        comm,
        state: field(3).chars().next().unwrap_or('?'),
        ppid: signed(4) as i32,
        pgrp: signed(5) as i32,
        session: signed(6) as i32,
        tty_nr: signed(7) as i32,
        minflt: num(10),
        majflt: num(12),
        utime: num(14),
        stime: num(15),
        cutime: signed(16).max(0) as u64,
        cstime: signed(17).max(0) as u64,
        priority: signed(18),
        nice: signed(19),
        num_threads: signed(20),
        starttime: num(22),
        vsize: num(23),
        rss: signed(24).max(0) as u64,
        processor: signed(39),
        policy: num(41) as u32,
    })
}

pub fn state_name(state: char) -> &'static str {
    match state {
        'R' => "running",
        'S' => "sleeping",
        'D' => "disk sleep",
        'Z' => "zombie",
        'T' => "stopped",
        't' => "tracing stop",
        'X' | 'x' => "dead",
        'K' => "wakekill",
        'W' => "waking",
        'P' => "parked",
        'I' => "idle",
        _ => "unknown",
    }
}

pub fn sched_policy_name(policy: u32) -> &'static str {
    match policy {
        0 => "SCHED_OTHER",
        1 => "SCHED_FIFO",
        2 => "SCHED_RR",
        3 => "SCHED_BATCH",
        5 => "SCHED_IDLE",
        6 => "SCHED_DEADLINE",
        _ => "unknown",
    }
}

/// Parses `Key:\tvalue` files such as `status` and `smaps_rollup`.
pub fn parse_kv(content: &str) -> HashMap<String, String> {
    content
        .lines()
        .filter_map(|line| {
            let (k, v) = line.split_once(':')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

/// `"1234 kB"` → `1234`.
pub fn parse_kb(value: &str) -> u64 {
    value
        .split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

pub fn parse_id_quad(value: &str) -> [u32; 4] {
    let mut out = [0u32; 4];
    for (slot, part) in out.iter_mut().zip(value.split_whitespace()) {
        *slot = part.parse().unwrap_or(0);
    }
    out
}

/// NUL separated argv. Trailing empty strings are dropped.
pub fn parse_nul_list(bytes: &[u8]) -> Vec<String> {
    let mut parts: Vec<String> = bytes
        .split(|b| *b == 0)
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();
    while parts.last().is_some_and(|p| p.is_empty()) {
        parts.pop();
    }
    parts
}

pub fn parse_environ(bytes: &[u8]) -> Vec<EnvVar> {
    parse_nul_list(bytes)
        .into_iter()
        .filter(|s| !s.is_empty())
        .map(|entry| match entry.split_once('=') {
            Some((k, v)) => EnvVar {
                key: k.to_string(),
                value: v.to_string(),
            },
            None => EnvVar {
                key: entry,
                value: String::new(),
            },
        })
        .collect()
}

pub fn classify_map(path: &str) -> MapKind {
    if path.is_empty() || path.starts_with("[anon") {
        MapKind::Anon
    } else if path == "[heap]" {
        MapKind::Heap
    } else if path.starts_with("[stack") {
        MapKind::Stack
    } else if matches!(path, "[vdso]" | "[vvar]" | "[vvar_vclock]" | "[vsyscall]") {
        MapKind::Vdso
    } else if path.starts_with("/memfd:") {
        MapKind::Memfd
    } else if path.ends_with(" (deleted)") {
        MapKind::Deleted
    } else if path.starts_with('[') {
        MapKind::Special
    } else {
        MapKind::File
    }
}

/// Parses `/proc/<pid>/maps`.
pub fn parse_maps(content: &str) -> Vec<MapEntry> {
    content.lines().filter_map(parse_map_line).collect()
}

fn parse_map_line(line: &str) -> Option<MapEntry> {
    let mut parts = line.splitn(6, ' ');
    let range = parts.next()?;
    let perms = parts.next()?.to_string();
    let offset = u64::from_str_radix(parts.next()?, 16).ok()?;
    let dev = parts.next()?.to_string();
    let inode = parts.next()?.parse().ok()?;
    let path = parts.next().unwrap_or("").trim_start().to_string();
    let (start, end) = range.split_once('-')?;
    Some(MapEntry {
        start: u64::from_str_radix(start, 16).ok()?,
        end: u64::from_str_radix(end, 16).ok()?,
        kind: classify_map(&path),
        perms,
        offset,
        dev,
        inode,
        path,
    })
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct FdInfo {
    pub pos: Option<u64>,
    pub flags: Option<u32>,
    pub mnt_id: Option<u64>,
    pub ino: Option<u64>,
}

pub fn parse_fdinfo(content: &str) -> FdInfo {
    let kv = parse_kv(content);
    FdInfo {
        pos: kv.get("pos").and_then(|v| v.parse().ok()),
        flags: kv.get("flags").and_then(|v| u32::from_str_radix(v, 8).ok()),
        mnt_id: kv.get("mnt_id").and_then(|v| v.parse().ok()),
        ino: kv.get("ino").and_then(|v| v.parse().ok()),
    }
}

/// Renders open(2) flags as `O_RDWR|O_CLOEXEC|...` using the host's values.
pub fn decode_open_flags(flags: u32) -> String {
    let flags = flags as i32;
    let mut out = vec![match flags & libc::O_ACCMODE {
        libc::O_RDONLY => "O_RDONLY",
        libc::O_WRONLY => "O_WRONLY",
        _ => "O_RDWR",
    }];
    let named = [
        (libc::O_CREAT, "O_CREAT"),
        (libc::O_EXCL, "O_EXCL"),
        (libc::O_NOCTTY, "O_NOCTTY"),
        (libc::O_TRUNC, "O_TRUNC"),
        (libc::O_APPEND, "O_APPEND"),
        (libc::O_NONBLOCK, "O_NONBLOCK"),
        (libc::O_DSYNC, "O_DSYNC"),
        (libc::O_ASYNC, "O_ASYNC"),
        (libc::O_DIRECT, "O_DIRECT"),
        (libc::O_DIRECTORY, "O_DIRECTORY"),
        (libc::O_NOFOLLOW, "O_NOFOLLOW"),
        (libc::O_NOATIME, "O_NOATIME"),
        (libc::O_CLOEXEC, "O_CLOEXEC"),
        (libc::O_PATH, "O_PATH"),
    ];
    for (bit, name) in named {
        if bit != 0 && flags & bit == bit {
            out.push(name);
        }
    }
    out.join("|")
}

/// Classifies a `/proc/<pid>/fd/N` link target.
/// Returns the kind, whether the target is marked deleted, and a socket/pipe inode.
pub fn classify_fd_target(target: &str) -> (FdKind, bool, Option<u64>) {
    let bracket_inode = |prefix: &str| -> Option<u64> {
        target
            .strip_prefix(prefix)?
            .strip_prefix('[')?
            .strip_suffix(']')?
            .parse()
            .ok()
    };
    if let Some(inode) = bracket_inode("socket:") {
        return (FdKind::Socket, false, Some(inode));
    }
    if let Some(inode) = bracket_inode("pipe:") {
        return (FdKind::Pipe, false, Some(inode));
    }
    let deleted = target.ends_with(" (deleted)");
    if target.starts_with("anon_inode:") {
        (FdKind::AnonInode, false, None)
    } else if target.starts_with("/memfd:") {
        (FdKind::Memfd, deleted, None)
    } else if target.starts_with("/dev/") && !deleted {
        (FdKind::Device, false, None)
    } else if target.starts_with('/') {
        (FdKind::File, deleted, None)
    } else {
        (FdKind::Other, false, None)
    }
}

pub fn tcp_state(code: u8) -> &'static str {
    match code {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        0x0C => "NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}

/// Decodes the kernel's hex `ADDR:PORT` notation. Addresses are printed as
/// host-endian 32-bit words, so convert with native byte order.
pub fn decode_inet(hex: &str) -> Option<String> {
    let (addr, port) = hex.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    match addr.len() {
        8 => {
            let word = u32::from_str_radix(addr, 16).ok()?;
            Some(format!("{}:{port}", Ipv4Addr::from(word.to_ne_bytes())))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for (i, chunk) in bytes.chunks_mut(4).enumerate() {
                let word = u32::from_str_radix(&addr[i * 8..i * 8 + 8], 16).ok()?;
                chunk.copy_from_slice(&word.to_ne_bytes());
            }
            let ip = Ipv6Addr::from(bytes);
            match ip.to_ipv4_mapped() {
                Some(v4) => Some(format!("[::ffff:{v4}]:{port}")),
                None => Some(format!("[{ip}]:{port}")),
            }
        }
        _ => None,
    }
}

/// Parses `/proc/<pid>/net/{tcp,tcp6,udp,udp6,raw,raw6}`.
pub fn parse_net_inet(content: &str, proto: &str) -> Vec<SocketEntry> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let code = u8::from_str_radix(f[3], 16).ok()?;
            let (tx, rx) = f[4].split_once(':').unwrap_or(("0", "0"));
            let state = if proto.starts_with("tcp") {
                tcp_state(code)
            } else if proto.starts_with("raw") {
                "RAW"
            } else if code == 0x07 {
                "UNCONN"
            } else {
                tcp_state(code)
            };
            Some(SocketEntry {
                proto: proto.to_string(),
                local: decode_inet(f[1])?,
                remote: decode_inet(f[2])?,
                state: state.to_string(),
                inode: f[9].parse().ok()?,
                fd: None,
                uid: f[7].parse().ok(),
                tx_queue: u64::from_str_radix(tx, 16).unwrap_or(0),
                rx_queue: u64::from_str_radix(rx, 16).unwrap_or(0),
                detail: String::new(),
            })
        })
        .collect()
}

/// Parses `/proc/<pid>/net/unix`.
pub fn parse_net_unix(content: &str) -> Vec<SocketEntry> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 7 {
                return None;
            }
            let flags = u32::from_str_radix(f[3], 16).unwrap_or(0);
            let kind = match f[4] {
                "0001" => "stream",
                "0002" => "dgram",
                "0005" => "seqpacket",
                _ => "unix",
            };
            let state = if flags & 0x0001_0000 != 0 {
                "LISTEN"
            } else {
                match f[5] {
                    "01" => "UNCONN",
                    "02" => "CONNECTING",
                    "03" => "CONNECTED",
                    "04" => "DISCONNECTING",
                    _ => "UNKNOWN",
                }
            };
            let path = f.get(7..).map(|p| p.join(" ")).unwrap_or_default();
            Some(SocketEntry {
                proto: format!("unix/{kind}"),
                local: if path.is_empty() {
                    "(unnamed)".into()
                } else {
                    path.clone()
                },
                remote: String::new(),
                state: state.to_string(),
                inode: f[6].parse().ok()?,
                detail: path,
                ..SocketEntry::default()
            })
        })
        .collect()
}

pub fn ethertype_name(proto: u16) -> String {
    match proto {
        0x0003 => "ALL".into(),
        0x0800 => "IPv4".into(),
        0x0806 => "ARP".into(),
        0x86DD => "IPv6".into(),
        0x88CC => "LLDP".into(),
        other => format!("0x{other:04x}"),
    }
}

/// Parses `/proc/<pid>/net/packet` (AF_PACKET, i.e. raw link-layer access).
/// The returned `local` field carries the interface index for later naming.
pub fn parse_net_packet(content: &str) -> Vec<SocketEntry> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 9 {
                return None;
            }
            let ty = match f[2] {
                "3" => "raw",
                "2" => "dgram",
                other => other,
            };
            // The kernel already converts the protocol to host order (ntohs).
            let proto = u16::from_str_radix(f[3], 16).unwrap_or(0);
            Some(SocketEntry {
                proto: "packet".into(),
                local: format!("ifindex {}", f[4]),
                remote: String::new(),
                state: format!("{ty}/{}", ethertype_name(proto)),
                inode: f[8].parse().ok()?,
                uid: f[7].parse().ok(),
                detail: f[4].to_string(),
                ..SocketEntry::default()
            })
        })
        .collect()
}

pub fn netlink_family(n: u32) -> &'static str {
    match n {
        0 => "route",
        2 => "usersock",
        4 => "sock_diag",
        6 => "xfrm",
        7 => "selinux",
        8 => "iscsi",
        9 => "audit",
        10 => "fib_lookup",
        11 => "connector",
        12 => "netfilter",
        15 => "kobject_uevent",
        16 => "generic",
        18 => "scsitransport",
        19 => "ecryptfs",
        20 => "rdma",
        21 => "crypto",
        _ => "netlink",
    }
}

/// Parses `/proc/<pid>/net/netlink`.
pub fn parse_net_netlink(content: &str) -> Vec<SocketEntry> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let family: u32 = f[1].parse().ok()?;
            Some(SocketEntry {
                proto: format!("netlink/{}", netlink_family(family)),
                local: format!("portid {}", f[2]),
                remote: String::new(),
                state: format!("groups {}", f[3]),
                inode: f[9].parse().ok()?,
                ..SocketEntry::default()
            })
        })
        .collect()
}

pub const CAP_NAMES: [&str; 41] = [
    "chown",
    "dac_override",
    "dac_read_search",
    "fowner",
    "fsetid",
    "kill",
    "setgid",
    "setuid",
    "setpcap",
    "linux_immutable",
    "net_bind_service",
    "net_broadcast",
    "net_admin",
    "net_raw",
    "ipc_lock",
    "ipc_owner",
    "sys_module",
    "sys_rawio",
    "sys_chroot",
    "sys_ptrace",
    "sys_pacct",
    "sys_admin",
    "sys_boot",
    "sys_nice",
    "sys_resource",
    "sys_time",
    "sys_tty_config",
    "mknod",
    "lease",
    "audit_write",
    "audit_control",
    "setfcap",
    "mac_override",
    "mac_admin",
    "syslog",
    "wake_alarm",
    "block_suspend",
    "audit_read",
    "perfmon",
    "bpf",
    "checkpoint_restore",
];

/// Capabilities that grant broad control over the host when effective.
pub const DANGEROUS_CAPS: [&str; 9] = [
    "sys_admin",
    "sys_ptrace",
    "sys_module",
    "sys_rawio",
    "net_admin",
    "net_raw",
    "bpf",
    "dac_override",
    "setuid",
];

pub fn decode_caps(hex: &str) -> Vec<String> {
    let mask = u64::from_str_radix(hex.trim(), 16).unwrap_or(0);
    (0..64)
        .filter(|bit| mask & (1u64 << bit) != 0)
        .map(|bit| match CAP_NAMES.get(bit) {
            Some(name) => format!("cap_{name}"),
            None => format!("cap_{bit}"),
        })
        .collect()
}

/// Parses the fixed-width `/proc/<pid>/limits` table using its header columns.
pub fn parse_limits(content: &str) -> Vec<LimitEntry> {
    let mut lines = content.lines();
    let Some(header) = lines.next() else {
        return Vec::new();
    };
    let (Some(soft), Some(hard), Some(units)) = (
        header.find("Soft Limit"),
        header.find("Hard Limit"),
        header.find("Units"),
    ) else {
        return Vec::new();
    };
    let slice = |line: &str, a: usize, b: usize| -> String {
        line.get(a.min(line.len())..b.min(line.len()))
            .unwrap_or("")
            .trim()
            .to_string()
    };
    lines
        .filter(|l| !l.trim().is_empty())
        .map(|line| LimitEntry {
            name: slice(line, 0, soft),
            soft: slice(line, soft, hard),
            hard: slice(line, hard, units),
            unit: slice(line, units, line.len()),
        })
        .collect()
}

pub fn parse_io(content: &str) -> IoStats {
    let kv = parse_kv(content);
    let get = |k: &str| kv.get(k).and_then(|v| v.parse().ok()).unwrap_or(0);
    IoStats {
        rchar: get("rchar"),
        wchar: get("wchar"),
        syscr: get("syscr"),
        syscw: get("syscw"),
        read_bytes: get("read_bytes"),
        write_bytes: get("write_bytes"),
        cancelled_write_bytes: get("cancelled_write_bytes"),
        available: !kv.is_empty(),
    }
}

/// `/etc/passwd` → uid to name.
pub fn parse_passwd(content: &str) -> HashMap<u32, String> {
    content
        .lines()
        .filter_map(|line| {
            let mut f = line.split(':');
            let name = f.next()?;
            let uid = f.nth(1)?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

/// Minimal ELF identification from the first 20 header bytes.
pub fn describe_elf(header: &[u8]) -> Option<String> {
    if header.len() < 20 || &header[..4] != b"\x7fELF" {
        return None;
    }
    let class = match header[4] {
        1 => "ELF32",
        2 => "ELF64",
        _ => "ELF?",
    };
    let little = header[5] == 1;
    let endian = if little { "LSB" } else { "MSB" };
    let half = |i: usize| {
        if little {
            u16::from_le_bytes([header[i], header[i + 1]])
        } else {
            u16::from_be_bytes([header[i], header[i + 1]])
        }
    };
    let kind = match half(16) {
        1 => "REL",
        2 => "EXEC",
        3 => "DYN",
        4 => "CORE",
        _ => "?",
    };
    let machine = match half(18) {
        0x03 => "x86",
        0x08 => "MIPS",
        0x14 => "PowerPC",
        0x15 => "PowerPC64",
        0x16 => "s390",
        0x28 => "ARM",
        0x3E => "x86-64",
        0xB7 => "AArch64",
        0xF3 => "RISC-V",
        0x102 => "LoongArch",
        _ => "unknown",
    };
    Some(format!("{class} {endian} {kind} {machine}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_with_hostile_comm() {
        let s = "4242 (evil) (x) S) R 1 4242 4242 0 -1 4194560 120 0 3 0 15 7 0 0 20 0 3 0 98765 1048576 300 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 5 0 0 0 0 0";
        let st = parse_stat(s).unwrap();
        assert_eq!(st.pid, 4242);
        assert_eq!(st.comm, "evil) (x) S");
        assert_eq!(st.state, 'R');
        assert_eq!(st.ppid, 1);
        assert_eq!(st.utime, 15);
        assert_eq!(st.stime, 7);
        assert_eq!(st.num_threads, 3);
        assert_eq!(st.starttime, 98765);
        assert_eq!(st.rss, 300);
        assert_eq!(st.processor, 5);
    }

    #[test]
    fn maps_kinds_and_paths_with_spaces() {
        let m = "55d0c8a4b000-55d0c8a4d000 r-xp 00002000 fd:01 1234                       /usr/bin/my tool\n\
                 7f0000000000-7f0000001000 rwxp 00000000 00:00 0 \n\
                 7f0000001000-7f0000002000 r-xp 00000000 00:01 77                         /memfd:payload (deleted)\n\
                 7f0000002000-7f0000003000 r-xp 00000000 fd:01 88                         /tmp/.x/libz.so (deleted)\n\
                 7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0                          [stack]\n";
        let maps = parse_maps(m);
        assert_eq!(maps.len(), 5);
        assert_eq!(maps[0].path, "/usr/bin/my tool");
        assert_eq!(maps[0].offset, 0x2000);
        assert_eq!(maps[0].kind, MapKind::File);
        assert!(maps[1].executable() && maps[1].writable());
        assert_eq!(maps[1].kind, MapKind::Anon);
        assert_eq!(maps[2].kind, MapKind::Memfd);
        assert_eq!(maps[3].kind, MapKind::Deleted);
        assert_eq!(maps[4].kind, MapKind::Stack);
        assert_eq!(maps[4].size(), 0x21000);
    }

    #[test]
    fn inet_decoding() {
        // 127.0.0.1:3306 on a little-endian host.
        if cfg!(target_endian = "little") {
            assert_eq!(decode_inet("0100007F:0CEA").unwrap(), "127.0.0.1:3306");
            assert_eq!(
                decode_inet("00000000000000000000000001000000:0016").unwrap(),
                "[::1]:22"
            );
            assert_eq!(
                decode_inet("0000000000000000FFFF00000100007F:01BB").unwrap(),
                "[::ffff:127.0.0.1]:443"
            );
        }
    }

    #[test]
    fn tcp_table() {
        let t = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   108        0 23456 1 0000000000000000 100 0 0 10 0\n";
        let s = parse_net_inet(t, "tcp");
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].state, "LISTEN");
        assert_eq!(s[0].inode, 23456);
        assert_eq!(s[0].uid, Some(108));
        assert!(s[0].is_listening());
    }

    #[test]
    fn unix_table() {
        let t = "Num       RefCount Protocol Flags    Type St Inode Path\n0000000000000000: 00000002 00000000 00010000 0001 01 3456 /run/app.sock\n0000000000000000: 00000003 00000000 00000000 0001 03 3457\n";
        let s = parse_net_unix(t);
        assert_eq!(s[0].state, "LISTEN");
        assert_eq!(s[0].local, "/run/app.sock");
        assert_eq!(s[1].state, "CONNECTED");
        assert_eq!(s[1].inode, 3457);
    }

    #[test]
    fn fd_targets() {
        assert_eq!(
            classify_fd_target("socket:[991]"),
            (FdKind::Socket, false, Some(991))
        );
        assert_eq!(
            classify_fd_target("pipe:[5]"),
            (FdKind::Pipe, false, Some(5))
        );
        assert_eq!(
            classify_fd_target("/tmp/x (deleted)"),
            (FdKind::File, true, None)
        );
        assert_eq!(
            classify_fd_target("/memfd:a (deleted)"),
            (FdKind::Memfd, true, None)
        );
        assert_eq!(
            classify_fd_target("/dev/null"),
            (FdKind::Device, false, None)
        );
        assert_eq!(
            classify_fd_target("anon_inode:[eventfd]").0,
            FdKind::AnonInode
        );
    }

    #[test]
    fn caps_and_flags() {
        let caps = decode_caps("0000000000003000");
        assert_eq!(caps, vec!["cap_net_admin", "cap_net_raw"]);
        assert_eq!(decode_caps("000001ffffffffff").len(), 41);
        let f = decode_open_flags((libc::O_RDWR | libc::O_CLOEXEC | libc::O_APPEND) as u32);
        assert_eq!(f, "O_RDWR|O_APPEND|O_CLOEXEC");
    }

    #[test]
    fn limits_table() {
        let t = "Limit                     Soft Limit           Hard Limit           Units     \nMax cpu time              unlimited            unlimited            seconds   \nMax open files            1024                 524288               files     \n";
        let l = parse_limits(t);
        assert_eq!(l.len(), 2);
        assert_eq!(l[1].name, "Max open files");
        assert_eq!(l[1].soft, "1024");
        assert_eq!(l[1].hard, "524288");
        assert_eq!(l[1].unit, "files");
    }

    #[test]
    fn environ_and_cmdline() {
        let env = parse_environ(b"A=1\0LD_PRELOAD=/tmp/x.so\0EMPTY=\0\0");
        assert_eq!(env.len(), 3);
        assert_eq!(env[1].key, "LD_PRELOAD");
        assert_eq!(
            parse_nul_list(b"/bin/sh\0-c\0id\0"),
            vec!["/bin/sh", "-c", "id"]
        );
    }

    #[test]
    fn elf_header() {
        let mut h = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        h.extend_from_slice(&[0; 8]);
        h.extend_from_slice(&3u16.to_le_bytes());
        h.extend_from_slice(&0x3Eu16.to_le_bytes());
        assert_eq!(describe_elf(&h).unwrap(), "ELF64 LSB DYN x86-64");
    }
}
