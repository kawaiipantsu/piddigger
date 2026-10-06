//! Triage heuristics over a [`Snapshot`].
//!
//! Every finding is a lead for the analyst, not a verdict. Each one carries
//! the evidence that triggered it and a suggested next step.

use serde::{Deserialize, Serialize};

use crate::model::{FdKind, MapKind, Snapshot};
use crate::procfs::DANGEROUS_CAPS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: &'static str,
    pub title: String,
    pub detail: &'static str,
    pub evidence: String,
    pub advice: &'static str,
}

const SHELLS: [&str; 9] = [
    "sh", "bash", "dash", "zsh", "ksh", "ash", "busybox", "fish", "tcsh",
];
const SERVICES: [&str; 18] = [
    "nginx",
    "apache2",
    "httpd",
    "php-fpm",
    "php",
    "java",
    "node",
    "python",
    "python3",
    "ruby",
    "perl",
    "postgres",
    "mysqld",
    "mariadbd",
    "tomcat",
    "uwsgi",
    "gunicorn",
    "redis-server",
];
const INTERPRETERS: [&str; 12] = [
    "python", "perl", "ruby", "node", "java", "bash", "sh", "dash", "busybox", "ld-linux", "php",
    "systemd",
];
const SYSTEM_NAMES: [&str; 12] = [
    "kworker",
    "kthreadd",
    "ksoftirqd",
    "migration",
    "rcu_",
    "sshd",
    "cron",
    "rsyslogd",
    "dbus-daemon",
    "systemd-",
    "udevd",
    "agetty",
];
const WRITABLE_DIRS: [&str; 5] = ["/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/", "/run/user/"];

fn in_writable_dir(path: &str) -> bool {
    WRITABLE_DIRS.iter().any(|d| path.starts_with(d)) || path.contains("/.")
}

fn base(path: &str) -> &str {
    let path = path.strip_suffix(" (deleted)").unwrap_or(path);
    path.rsplit('/').next().unwrap_or(path)
}

fn is_shell(comm: &str) -> bool {
    SHELLS.contains(&comm)
}

fn is_service(comm: &str) -> bool {
    let c = comm.trim_end_matches(|ch: char| ch.is_ascii_digit() || ch == '.');
    SERVICES.iter().any(|s| c == *s || comm.starts_with(s))
}

pub fn analyze(s: &Snapshot) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut add = |severity, category, title: String, detail, evidence: String, advice| {
        out.push(Finding {
            severity,
            category,
            title,
            detail,
            evidence,
            advice,
        })
    };

    if s.exited {
        add(
            Severity::Info,
            "process",
            "Target process has exited".into(),
            "The PID no longer exists. The views show the last snapshot collected while it ran.",
            format!("pid {}", s.ident.pid),
            "Preserve what was already collected and check for a respawned process with the same name.",
        );
    }

    // --- Executable --------------------------------------------------------
    let exe = &s.exe;
    if exe.memfd {
        add(
            Severity::High,
            "exe",
            "Running from a memfd (fileless execution)".into(),
            "The executable is an anonymous memory file created with memfd_create(2). The binary never existed on disk, a common fileless malware technique.",
            exe.path.clone(),
            "Copy the executable into the case right away (Evidence → snapshot): /proc/<pid>/exe is the only copy.",
        );
    } else if exe.deleted {
        add(
            Severity::High,
            "exe",
            "Executable deleted from disk while running".into(),
            "The file backing this process was unlinked after it started. Droppers often delete themselves to hinder recovery.",
            exe.path.clone(),
            "Recover the binary via the snapshot (copied from /proc/<pid>/exe) and compare its SHA-256 with package checksums.",
        );
    }
    if WRITABLE_DIRS.iter().any(|d| exe.path.starts_with(d)) {
        add(
            Severity::High,
            "exe",
            "Executable in a world-writable location".into(),
            "Legitimate services rarely execute from /tmp, /dev/shm or /var/tmp.",
            exe.path.clone(),
            "Identify who wrote the file (ctime, owner) and look for persistence that launches it.",
        );
    } else if exe.path.contains("/.") {
        add(
            Severity::Medium,
            "exe",
            "Executable inside a hidden directory".into(),
            "Dot-directories hide tooling from casual listings. Some user tools install there legitimately (~/.local/bin, ~/.cargo/bin).",
            exe.path.clone(),
            "Check the file owner and creation time and whether a package or user installed it.",
        );
    }
    if !exe.path.is_empty() && !exe.memfd {
        let exe_base = base(&exe.path);
        let comm = &s.ident.comm;
        // comm is truncated to 15 bytes by the kernel.
        let matches = exe_base.starts_with(comm.as_str()) || comm.starts_with(exe_base);
        let interpreter = INTERPRETERS.iter().any(|i| exe_base.starts_with(i));
        if !matches && !interpreter {
            let mimics_system = SYSTEM_NAMES.iter().any(|n| comm.starts_with(n));
            add(
                if mimics_system { Severity::High } else { Severity::Low },
                "masquerade",
                format!("Process name '{comm}' differs from executable '{exe_base}'"),
                "The task name (comm) can be set freely with prctl(PR_SET_NAME). Multi-process programs rename workers legitimately; a name that imitates a system daemon is a classic masquerade.",
                format!("comm={comm} exe={}", exe.path),
                "Confirm whether the program renames itself legitimately; compare with the package that owns the executable.",
            );
        }
    }
    if let Some(argv0) = s.ident.cmdline.first() {
        if argv0.starts_with('[') && argv0.ends_with(']') && !exe.path.is_empty() {
            add(
                Severity::High,
                "masquerade",
                "User-space process disguised as a kernel thread".into(),
                "Kernel threads have no executable and no command line. A bracketed argv[0] on a process with an executable is a classic disguise.",
                format!("argv[0]={argv0} exe={}", exe.path),
                "Treat as suspicious: preserve the executable and memory before containment.",
            );
        }
    }

    // --- Process tree --------------------------------------------------------
    let comm = s.ident.comm.as_str();
    if is_shell(comm) {
        if let Some(parent) = s.ancestry.iter().take(3).find(|p| is_service(&p.comm)) {
            add(
                Severity::High,
                "lineage",
                format!("Shell spawned by network service '{}'", parent.comm),
                "An interactive shell descending from a web server, interpreter or database is a common sign of remote code execution or a web shell.",
                format!("{} ({}) → … → {} ({})", parent.comm, parent.pid, comm, s.ident.pid),
                "Inspect the service logs around the process start time and capture the shell's network activity.",
            );
        }
        let std_sockets: Vec<i32> = s
            .fds
            .iter()
            .filter(|f| f.fd <= 2 && f.kind == FdKind::Socket)
            .map(|f| f.fd)
            .collect();
        if std_sockets.len() >= 2 {
            add(
                Severity::High,
                "network",
                "Shell with standard I/O redirected to a socket".into(),
                "stdin/stdout/stderr of a shell connected to a network socket is the defining trait of a reverse or bind shell.",
                format!("fds {std_sockets:?} are sockets"),
                "Record the remote endpoint from the Network tab and capture traffic before containment.",
            );
        }
    }
    if s.ident.hidden_from_listing {
        add(
            Severity::High,
            "rootkit",
            "PID hidden from the /proc directory listing".into(),
            "The process answers on /proc/<pid> but is missing from readdir(/proc). User-mode and kernel rootkits hide processes this way.",
            format!("pid {}", s.ident.pid),
            "Assume the host is compromised at a deep level; prefer offline memory acquisition.",
        );
    }

    // --- Environment ---------------------------------------------------------
    for var in &s.environ {
        match var.key.as_str() {
            "LD_PRELOAD" | "LD_AUDIT" if !var.value.is_empty() => add(
                Severity::High,
                "injection",
                format!("{} is set", var.key),
                "The dynamic loader injects these libraries into the process. Userland rootkits and credential stealers rely on this.",
                format!("{}={}", var.key, var.value),
                "Hash and preserve the referenced libraries; check other processes for the same variable.",
            ),
            "LD_LIBRARY_PATH" if var.value.split(':').any(in_writable_dir_dir) => add(
                Severity::Medium,
                "injection",
                "LD_LIBRARY_PATH points into a writable location".into(),
                "Library search paths in writable directories allow library hijacking.",
                format!("{}={}", var.key, var.value),
                "List the libraries actually mapped from these directories (Memory → libraries).",
            ),
            "HISTFILE" if var.value == "/dev/null" || var.value.is_empty() => add(
                Severity::Medium,
                "anti-forensics",
                "Shell history disabled via HISTFILE".into(),
                "Pointing HISTFILE at /dev/null prevents the shell from writing history, a common anti-forensics step.",
                format!("HISTFILE={}", var.value),
                "Rely on live capture (strace process/exec tracing, audit logs) instead of history files.",
            ),
            "HISTSIZE" | "HISTFILESIZE" if var.value == "0" => add(
                Severity::Medium,
                "anti-forensics",
                format!("Shell history size forced to 0 ({})", var.key),
                "A zero history size prevents commands from being recorded.",
                format!("{}={}", var.key, var.value),
                "Rely on live capture (strace process/exec tracing, audit logs) instead of history files.",
            ),
            _ => {}
        }
    }
    if !s.host.ld_so_preload.is_empty() {
        add(
            Severity::High,
            "injection",
            "/etc/ld.so.preload is active on this host".into(),
            "Every dynamically linked program loads these libraries. The file is empty on almost all systems and is a known rootkit persistence point.",
            s.host.ld_so_preload.join(", "),
            "Preserve /etc/ld.so.preload and the libraries it names; check whether they are mapped in this process.",
        );
    }

    // --- Memory mappings -----------------------------------------------------
    let rwx: Vec<_> = s
        .maps
        .iter()
        .filter(|m| m.writable() && m.executable())
        .collect();
    if !rwx.is_empty() {
        add(
            Severity::Medium,
            "memory",
            format!("{} writable + executable (RWX) mapping(s)", rwx.len()),
            "RWX memory allows code to be written and executed in place. JIT runtimes use it, but it is also the classic shellcode staging area.",
            rwx.iter()
                .take(4)
                .map(|m| format!("{:x}-{:x} {}", m.start, m.end, if m.path.is_empty() { "[anon]" } else { &m.path }))
                .collect::<Vec<_>>()
                .join("; "),
            "If the process is not a JIT runtime (JVM, browsers, node), dump memory with gcore for offline analysis.",
        );
    }
    let anon_exec: Vec<_> = s
        .maps
        .iter()
        .filter(|m| m.executable() && !m.writable() && m.kind == MapKind::Anon)
        .collect();
    if !anon_exec.is_empty() {
        add(
            Severity::Low,
            "memory",
            format!("{} anonymous executable mapping(s)", anon_exec.len()),
            "Executable memory without a backing file can hold injected or unpacked code. JIT compilers also create it.",
            anon_exec
                .iter()
                .take(4)
                .map(|m| format!("{:x}-{:x} {}", m.start, m.end, m.perms))
                .collect::<Vec<_>>()
                .join("; "),
            "Correlate with the process type; preserve memory if it is not a JIT runtime.",
        );
    }
    let mut suspicious_libs: Vec<&str> = s
        .maps
        .iter()
        .filter(|m| m.executable())
        .filter(|m| matches!(m.kind, MapKind::Deleted | MapKind::Memfd) || in_writable_dir(&m.path))
        .map(|m| m.path.as_str())
        .collect();
    suspicious_libs.sort_unstable();
    suspicious_libs.dedup();
    // A deleted main executable is already reported above.
    suspicious_libs.retain(|p| *p != exe.path);
    if !suspicious_libs.is_empty() {
        add(
            Severity::High,
            "injection",
            format!("{} executable mapping(s) from deleted, memfd or writable paths", suspicious_libs.len()),
            "Code mapped from a deleted file, a memfd or /tmp-like directories points to injected libraries or in-memory loaders.",
            suspicious_libs.join("; "),
            "Dump process memory and recover the mapped files; check the loader environment (LD_PRELOAD).",
        );
    }

    // --- Files -----------------------------------------------------------------
    let deleted: Vec<_> = s
        .fds
        .iter()
        .filter(|f| f.deleted && matches!(f.kind, FdKind::File | FdKind::Memfd))
        .collect();
    if !deleted.is_empty() {
        add(
            Severity::Medium,
            "files",
            format!("{} deleted-but-open file(s)", deleted.len()),
            "These files are unlinked but still readable through /proc/<pid>/fd. Malware hides payloads and logs this way; services also keep rotated logs open.",
            deleted
                .iter()
                .take(5)
                .map(|f| format!("fd {} → {}", f.fd, f.target))
                .collect::<Vec<_>>()
                .join("; "),
            "Recover them with the snapshot or the Files tab (c) before the process exits.",
        );
    }
    if s.ident.cwd.ends_with(" (deleted)") || in_writable_dir(&format!("{}/", s.ident.cwd)) {
        add(
            Severity::Low,
            "files",
            "Working directory is deleted or world-writable".into(),
            "Attack tooling is often staged and run from temporary directories.",
            s.ident.cwd.clone(),
            "List the directory contents and preserve anything unusual.",
        );
    }

    // --- Network -------------------------------------------------------------------
    let packet: Vec<_> = s.sockets.iter().filter(|x| x.proto == "packet").collect();
    if !packet.is_empty() {
        add(
            Severity::High,
            "network",
            "Raw link-layer (AF_PACKET) socket open".into(),
            "AF_PACKET sockets see every frame on an interface. Expected for tcpdump, DHCP clients and IDS sensors; otherwise a sniffer or a BPF backdoor trigger.",
            packet
                .iter()
                .map(|x| format!("fd {} {} on {}", x.fd.unwrap_or(-1), x.state, x.local))
                .collect::<Vec<_>>()
                .join("; "),
            "Confirm the program should sniff traffic. BPF backdoors (e.g. BPFDoor) use packet sockets with filters.",
        );
    }
    let raw: Vec<_> = s
        .sockets
        .iter()
        .filter(|x| x.proto.starts_with("raw"))
        .collect();
    if !raw.is_empty() {
        add(
            Severity::Medium,
            "network",
            format!("{} raw IP socket(s)", raw.len()),
            "Raw sockets craft or receive arbitrary IP packets: ping and routing daemons, but also covert channels and scanners.",
            raw.iter().map(|x| x.local.clone()).collect::<Vec<_>>().join("; "),
            "Check the protocol in use and capture traffic with tcpdump.",
        );
    }
    let listening: Vec<_> = s
        .sockets
        .iter()
        .filter(|x| {
            x.is_listening() && !x.proto.starts_with("unix") && !x.proto.starts_with("netlink")
        })
        .collect();
    if !listening.is_empty() {
        let public = listening
            .iter()
            .any(|x| x.local.starts_with("0.0.0.0:") || x.local.starts_with("[::]:"));
        add(
            if public { Severity::Low } else { Severity::Info },
            "network",
            format!("Listening on {} socket(s){}", listening.len(), if public { " (all interfaces)" } else { "" }),
            "Listening sockets accept inbound connections. Verify each port belongs to the expected service.",
            listening.iter().map(|x| format!("{} {}", x.proto, x.local)).collect::<Vec<_>>().join("; "),
            "Compare with the service's configuration and firewall policy.",
        );
    }
    let established: Vec<_> = s
        .sockets
        .iter()
        .filter(|x| x.state == "ESTABLISHED" && !x.proto.starts_with("unix"))
        .filter(|x| {
            !x.remote.starts_with("127.")
                && !x.remote.starts_with("[::1]")
                && !x.remote.starts_with("[::ffff:127.")
        })
        .collect();
    if !established.is_empty() {
        add(
            Severity::Info,
            "network",
            format!("{} established connection(s) to non-loopback peers", established.len()),
            "Active network sessions. Outbound sessions from non-network software deserve attention.",
            established.iter().take(6).map(|x| format!("{} → {}", x.local, x.remote)).collect::<Vec<_>>().join("; "),
            "Look up remote addresses in threat intelligence and capture traffic if unexpected.",
        );
    }

    // --- Privileges ----------------------------------------------------------------
    let [ruid, euid, ..] = s.ident.uid;
    if ruid != 0 && euid == 0 {
        add(
            Severity::Medium,
            "privilege",
            "Effective UID 0 with a non-root real UID".into(),
            "The process gained root through a set-uid binary or an exploit while keeping the caller's real UID.",
            format!("uid real={ruid} effective={euid}"),
            "Identify the set-uid program and whether this elevation is expected.",
        );
    }
    let dangerous: Vec<&str> = s
        .security
        .cap_eff
        .names
        .iter()
        .map(|c| c.trim_start_matches("cap_"))
        .filter(|c| DANGEROUS_CAPS.contains(c))
        .collect();
    if euid != 0 && !dangerous.is_empty() {
        add(
            Severity::Medium,
            "privilege",
            "Non-root process holds powerful capabilities".into(),
            "These effective capabilities grant near-root power and are a common privilege escalation or persistence result.",
            dangerous.join(", "),
            "Check file capabilities on the executable (getcap) and the service unit's AmbientCapabilities.",
        );
    }
    if s.security.tracer_pid > 0 {
        add(
            Severity::Medium,
            "debug",
            format!("Process is being traced by PID {}", s.security.tracer_pid),
            "Another process is attached with ptrace. Debuggers and strace do this, but so do injectors and credential stealers.",
            format!(
                "TracerPid={} ({})",
                s.security.tracer_pid,
                s.security.tracer_comm.clone().unwrap_or_else(|| "?".into())
            ),
            "Investigate the tracer process too; ptrace-based tools in piddigger will fail while it is attached.",
        );
    }

    // --- Containers / namespaces -------------------------------------------------
    let differing: Vec<&str> = s
        .namespaces
        .iter()
        .filter(|n| n.differs_from_init())
        .map(|n| n.name.as_str())
        .collect();
    if !differing.is_empty() {
        add(
            Severity::Info,
            "namespace",
            format!("Runs in {} non-init namespace(s)", differing.len()),
            "The process is isolated from PID 1 (container, sandbox or systemd hardening). Paths and network data are relative to its namespaces.",
            differing.join(", "),
            "Use the cgroup path to map the process to its container or unit.",
        );
    }
    if s.ident.age_secs > 0.0 && s.ident.age_secs < 600.0 {
        add(
            Severity::Info,
            "process",
            "Process started in the last 10 minutes".into(),
            "Recently started processes are good pivots around the time of an alert.",
            format!("started {:.0}s ago", s.ident.age_secs),
            "Correlate the start time with authentication and service logs.",
        );
    }
    if !s.errors.is_empty() && s.host.collector_uid != 0 {
        add(
            Severity::Info,
            "visibility",
            "Limited visibility: not running as root".into(),
            "Some /proc entries need root or CAP_SYS_PTRACE. Findings may be incomplete.",
            s.errors
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
            "Re-run piddigger with sudo for complete collection.",
        );
    }

    out.sort_by_key(|f| std::cmp::Reverse(f.severity));
    out
}

fn in_writable_dir_dir(dir: &str) -> bool {
    in_writable_dir(&format!("{}/", dir.trim_end_matches('/')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo;

    #[test]
    fn demo_snapshot_triggers_key_findings() {
        // The demo target masquerades as "nginx" from a deleted binary with an
        // injected preload and RWX memory. Shell/reverse-shell findings apply to
        // its children, which analyze() does not descend into.
        let f = analyze(&demo::snapshot(0));
        let titles: Vec<&str> = f.iter().map(|x| x.title.as_str()).collect();
        assert_eq!(
            f[0].severity,
            Severity::High,
            "top finding should be High: {titles:?}"
        );
        assert!(
            titles.iter().any(|t| t.contains("deleted from disk")),
            "{titles:?}"
        );
        assert!(
            titles.iter().any(|t| t.contains("kernel thread")),
            "{titles:?}"
        );
        assert!(
            titles.iter().any(|t| t.contains("LD_PRELOAD")),
            "{titles:?}"
        );
        assert!(
            titles.iter().any(|t| t.contains("ld.so.preload")),
            "{titles:?}"
        );
        assert!(titles.iter().any(|t| t.contains("RWX")), "{titles:?}");
        assert!(
            titles
                .iter()
                .any(|t| t.contains("deleted, memfd or writable")),
            "{titles:?}"
        );
    }

    #[test]
    fn quiet_process_has_no_high_findings() {
        let mut s = Snapshot::default();
        s.ident.comm = "cat".into();
        s.exe.path = "/usr/bin/cat".into();
        assert!(analyze(&s).iter().all(|f| f.severity < Severity::Medium));
    }
}
