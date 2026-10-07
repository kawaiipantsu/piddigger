//! Opt-in live capture with standard Linux tools (strace, ltrace, perf,
//! bpftrace, tcpdump, gdb). Output is streamed to the UI and written to the
//! case directory, where it is hashed once the run finishes.
//!
//! Every profile declares how intrusive it is so the analyst can make an
//! informed decision before touching a live system.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::model::Snapshot;
use crate::util;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Impact {
    /// Kernel-side observation (eBPF, perf, packet capture). Target is not stopped.
    Observe,
    /// ptrace attach. Slows the target; visible through TracerPid.
    Ptrace,
    /// Stops the target while the tool runs (gdb, gcore).
    Pause,
}

impl Impact {
    pub fn label(self) -> &'static str {
        match self {
            Impact::Observe => "observe",
            Impact::Ptrace => "ptrace",
            Impact::Pause => "pause",
        }
    }
    pub fn warning(self) -> &'static str {
        match self {
            Impact::Observe => "Kernel-side observation. The target is not stopped, but tracing adds overhead to the host.",
            Impact::Ptrace => "Attaches with ptrace: the target slows down and can detect TracerPid. Only one tracer can attach at a time.",
            Impact::Pause => "Stops every thread of the target while the tool runs. Timeouts in the target are possible.",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Profile {
    pub id: &'static str,
    pub title: &'static str,
    pub tool: &'static str,
    pub package: &'static str,
    pub impact: Impact,
    pub timed: bool,
    pub about: &'static str,
}

pub const PROFILES: &[Profile] = &[
    Profile { id: "strace-all", title: "Syscalls · everything", tool: "strace", package: "strace", impact: Impact::Ptrace, timed: true, about: "All system calls of every thread with timestamps, durations and decoded fds (-f -tt -T -yy)." },
    Profile { id: "strace-file", title: "Syscalls · file access", tool: "strace", package: "strace", impact: Impact::Ptrace, timed: true, about: "open/stat/unlink/rename/... — which paths the process touches right now." },
    Profile { id: "strace-net", title: "Syscalls · network", tool: "strace", package: "strace", impact: Impact::Ptrace, timed: true, about: "socket/connect/accept/send/recv with decoded addresses." },
    Profile { id: "strace-proc", title: "Syscalls · process lifecycle", tool: "strace", package: "strace", impact: Impact::Ptrace, timed: true, about: "fork/clone/execve/exit/kill — what the process spawns and executes." },
    Profile { id: "strace-count", title: "Syscalls · summary table", tool: "strace", package: "strace", impact: Impact::Ptrace, timed: true, about: "Counts, errors and time per syscall, printed when the run ends." },
    Profile { id: "ltrace", title: "Library calls", tool: "ltrace", package: "ltrace", impact: Impact::Ptrace, timed: true, about: "Dynamic library calls (libc and friends) with timestamps." },
    Profile { id: "perf-stat", title: "CPU counters", tool: "perf", package: "linux-perf", impact: Impact::Observe, timed: true, about: "Task clock, context switches, migrations, page faults, cycles and instructions." },
    Profile { id: "perf-record", title: "CPU profile · hot functions", tool: "perf", package: "linux-perf", impact: Impact::Observe, timed: true, about: "99 Hz sampling with call graphs; report of the hottest DSOs and symbols. perf.data kept in the case." },
    Profile { id: "bpf-syscalls", title: "eBPF · syscall counts", tool: "bpftrace", package: "bpftrace", impact: Impact::Observe, timed: true, about: "Per-syscall counts collected in the kernel without ptrace." },
    Profile { id: "bpf-files", title: "eBPF · file opens", tool: "bpftrace", package: "bpftrace", impact: Impact::Observe, timed: true, about: "Every openat() path with thread id, captured without ptrace." },
    Profile { id: "bpf-exec", title: "eBPF · fork & exec", tool: "bpftrace", package: "bpftrace", impact: Impact::Observe, timed: true, about: "Children forked by the target and programs it executes." },
    Profile { id: "tcpdump", title: "Traffic on the target's ports", tool: "tcpdump", package: "tcpdump", impact: Impact::Observe, timed: true, about: "Packet capture filtered to the TCP/UDP ports the process currently uses. pcap kept in the case." },
    Profile { id: "gdb-bt", title: "Thread backtraces", tool: "gdb", package: "gdb", impact: Impact::Pause, timed: false, about: "One-shot stack trace of every thread (briefly stops the process)." },
    Profile { id: "gcore", title: "Memory image (core dump)", tool: "gcore", package: "gdb", impact: Impact::Pause, timed: false, about: "Full process memory image for offline analysis (volatility, gdb, strings). Pauses the target while writing." },
];

pub fn find_in_path(tool: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")
        .unwrap_or_else(|| "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    std::env::split_paths(&path)
        .chain(["/usr/sbin", "/sbin"].iter().map(PathBuf::from))
        .map(|dir| dir.join(tool))
        .find(|p| {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
}

/// Kernel ptrace policy (Yama). 0 classic, 1 restricted, 2 admin-only, 3 disabled.
pub fn ptrace_scope() -> Option<u8> {
    fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Plain-text checklist for `--tools`: every external tool the trace menu can
/// run, whether it is installed, the privileges it needs, and the apt command
/// for whatever is missing.
pub fn checklist_text() -> String {
    checklist(
        find_in_path,
        unsafe { libc::geteuid() } == 0,
        ptrace_scope(),
    )
}

fn checklist(locate: impl Fn(&str) -> Option<PathBuf>, root: bool, scope: Option<u8>) -> String {
    let mut out = format!(
        "piddigger {} — trace & capture tools\n\
         Optional: /proc collection works without them; the trace menu (R) needs them.\n\n\
         {:<10}{:<12}{:<9}STATUS\n",
        env!("CARGO_PKG_VERSION"),
        "TOOL",
        "PACKAGE",
        "IMPACT"
    );
    let mut seen: Vec<&str> = Vec::new();
    let mut missing: Vec<&str> = Vec::new();
    for p in PROFILES {
        if seen.contains(&p.tool) {
            continue;
        }
        seen.push(p.tool);
        let status = match locate(p.tool) {
            Some(path) => format!("ok  {}", path.display()),
            None => {
                if !missing.contains(&p.package) {
                    missing.push(p.package);
                }
                "MISSING".into()
            }
        };
        let uses: Vec<&Profile> = PROFILES.iter().filter(|q| q.tool == p.tool).collect();
        out.push_str(&format!(
            "{:<10}{:<12}{:<9}{status}\n{:10}{}\n",
            p.tool,
            p.package,
            p.impact.label(),
            "",
            capture_names(&uses)
        ));
    }

    out.push_str("\nPrivileges\n");
    out.push_str(if root {
        "  root          yes\n"
    } else {
        "  root          no — run with sudo for complete /proc visibility and ptrace/pause captures\n"
    });
    if let Some(scope) = scope {
        let note = match scope {
            0 => "classic",
            1 if root => "restricted — fine as root",
            1 => "restricted — ptrace/pause captures need sudo",
            2 => "admin-only — ptrace/pause captures need CAP_SYS_PTRACE",
            _ => "disabled — ptrace/pause captures cannot attach until reboot",
        };
        out.push_str(&format!("  ptrace_scope  {scope} {note}\n"));
    }

    if missing.is_empty() {
        out.push_str("\nAll capture tools are installed.\n");
    } else {
        out.push_str(&format!(
            "\nInstall the missing tools:\n  sudo apt install {}\n",
            missing.join(" ")
        ));
    }
    out
}

/// Joins profile titles, dropping a repeated "Group · " prefix.
fn capture_names(profiles: &[&Profile]) -> String {
    let mut prev = "";
    profiles
        .iter()
        .map(|p| match p.title.split_once(" · ") {
            Some((head, tail)) if head == prev => tail,
            Some((head, _)) => {
                prev = head;
                p.title
            }
            None => {
                prev = "";
                p.title
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Builds the BPF filter for the target's current TCP/UDP ports.
pub fn port_filter(snap: &Snapshot) -> Option<String> {
    let mut ports: Vec<u16> = snap
        .sockets
        .iter()
        .filter(|s| s.proto.starts_with("tcp") || s.proto.starts_with("udp"))
        .filter_map(|s| s.local.rsplit(':').next()?.parse().ok())
        .filter(|p| *p != 0)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports.truncate(32);
    (!ports.is_empty()).then(|| {
        ports
            .iter()
            .map(|p| format!("port {p}"))
            .collect::<Vec<_>>()
            .join(" or ")
    })
}

/// Command stages for a profile. Each stage is an argv vector.
pub fn commands(
    p: &Profile,
    pid: i32,
    secs: u64,
    out_dir: &Path,
    stamp: &str,
    snap: &Snapshot,
) -> Result<(Vec<Vec<String>>, Vec<PathBuf>), String> {
    let pid_s = pid.to_string();
    let v = |args: &[&str]| args.iter().map(|s| s.to_string()).collect::<Vec<String>>();
    let strace = |filter: Option<&str>| {
        let mut a = v(&[
            "strace", "-f", "-tt", "-T", "-yy", "-s", "256", "-p", &pid_s,
        ]);
        if let Some(f) = filter {
            a.push("-e".into());
            a.push(format!("trace={f}"));
        }
        a
    };
    let interval = format!("interval:s:{secs} {{ exit(); }}");
    Ok(match p.id {
        "strace-all" => (vec![strace(None)], vec![]),
        "strace-file" => (vec![strace(Some("%file"))], vec![]),
        "strace-net" => (vec![strace(Some("%network"))], vec![]),
        "strace-proc" => (vec![strace(Some("%process"))], vec![]),
        "strace-count" => (vec![v(&["strace", "-c", "-f", "-p", &pid_s])], vec![]),
        "ltrace" => (vec![v(&["ltrace", "-f", "-tt", "-s", "128", "-p", &pid_s])], vec![]),
        "perf-stat" => (vec![v(&["perf", "stat", "-p", &pid_s, "--", "sleep", &secs.to_string()])], vec![]),
        "perf-record" => {
            let data = out_dir.join(format!("perf-{stamp}.data"));
            let d = data.to_string_lossy().into_owned();
            (
                vec![
                    v(&["perf", "record", "-F", "99", "-g", "-p", &pid_s, "-o", &d, "--", "sleep", &secs.to_string()]),
                    v(&["perf", "report", "--stdio", "--no-children", "-i", &d, "--sort", "dso,sym", "--percent-limit", "0.5"]),
                ],
                vec![data],
            )
        }
        "bpf-syscalls" => (
            vec![v(&["bpftrace", "-e", &format!("tracepoint:syscalls:sys_enter_* /pid == {pid}/ {{ @[probe] = count(); }} {interval}")])],
            vec![],
        ),
        "bpf-files" => (
            vec![v(&["bpftrace", "-e", &format!("tracepoint:syscalls:sys_enter_openat /pid == {pid}/ {{ time(\"%H:%M:%S \"); printf(\"tid=%d %s\\n\", tid, str(args->filename)); }} {interval}")])],
            vec![],
        ),
        "bpf-exec" => (
            vec![v(&["bpftrace", "-e", &format!(
                "tracepoint:sched:sched_process_fork /args->parent_pid == {pid}/ {{ time(\"%H:%M:%S \"); printf(\"fork %d -> %d\\n\", args->parent_pid, args->child_pid); }} \
                 tracepoint:syscalls:sys_enter_execve /pid == {pid}/ {{ time(\"%H:%M:%S \"); printf(\"execve %s\\n\", str(args->filename)); }} {interval}"
            )])],
            vec![],
        ),
        "tcpdump" => {
            let filter = port_filter(snap).ok_or("the target has no TCP/UDP ports to filter on")?;
            let pcap = out_dir.join(format!("tcpdump-{stamp}.pcap"));
            let mut a = v(&["tcpdump", "-i", "any", "-nn", "-l", "-U", "-w", &pcap.to_string_lossy(), "--print"]);
            a.extend(filter.split(' ').map(str::to_string));
            (vec![a], vec![pcap])
        }
        "gdb-bt" => (
            vec![v(&["gdb", "-p", &pid_s, "-batch", "-nx", "-ex", "set pagination off", "-ex", "info threads", "-ex", "thread apply all bt"])],
            vec![],
        ),
        "gcore" => {
            let prefix = out_dir.join(format!("core-{stamp}"));
            (
                vec![v(&["gcore", "-o", &prefix.to_string_lossy(), &pid_s])],
                vec![PathBuf::from(format!("{}.{pid}", prefix.to_string_lossy()))],
            )
        }
        other => return Err(format!("unknown profile {other}")),
    })
}

#[derive(Debug, Clone, PartialEq)]
pub enum RunState {
    Running,
    Finished(Option<i32>),
    Failed(String),
}

pub struct Run {
    pub profile: Profile,
    pub started: Instant,
    pub started_at: String,
    pub secs: u64,
    pub log_path: PathBuf,
    pub artifacts: Vec<PathBuf>,
    pub argv: Vec<Vec<String>>,
    pub lines: Arc<Mutex<VecDeque<String>>>,
    pub line_count: Arc<Mutex<u64>>,
    pub state: Arc<Mutex<RunState>>,
    stop: Arc<AtomicBool>,
    pub registered: bool,
}

const TAIL_LINES: usize = 2000;

impl Run {
    pub fn start(
        profile: Profile,
        argv: Vec<Vec<String>>,
        secs: u64,
        log_path: PathBuf,
        artifacts: Vec<PathBuf>,
    ) -> std::io::Result<Run> {
        let log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&log_path)?;
        let log = Arc::new(Mutex::new(log));
        let lines = Arc::new(Mutex::new(VecDeque::new()));
        let count = Arc::new(Mutex::new(0u64));
        let state = Arc::new(Mutex::new(RunState::Running));
        let stop = Arc::new(AtomicBool::new(false));
        let run = Run {
            profile,
            started: Instant::now(),
            started_at: util::now_rfc3339(),
            secs,
            log_path,
            artifacts,
            argv: argv.clone(),
            lines: lines.clone(),
            line_count: count.clone(),
            state: state.clone(),
            stop: stop.clone(),
            registered: false,
        };
        let sink = Sink { log, lines, count };
        let timed = profile.timed;
        thread::spawn(move || {
            let result = run_stages(&argv, timed, secs, &stop, &sink);
            *state.lock().unwrap() = result;
        });
        Ok(run)
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn state(&self) -> RunState {
        self.state.lock().unwrap().clone()
    }

    pub fn is_running(&self) -> bool {
        self.state() == RunState::Running
    }

    pub fn tail(&self, n: usize) -> Vec<String> {
        let lines = self.lines.lock().unwrap();
        lines
            .iter()
            .skip(lines.len().saturating_sub(n))
            .cloned()
            .collect()
    }

    /// Total number of output lines captured so far (not just the retained tail).
    pub fn captured_lines(&self) -> u64 {
        *self.line_count.lock().unwrap()
    }
}

#[derive(Clone)]
struct Sink {
    log: Arc<Mutex<File>>,
    lines: Arc<Mutex<VecDeque<String>>>,
    count: Arc<Mutex<u64>>,
}

impl Sink {
    fn line(&self, line: &str) {
        let _ = writeln!(self.log.lock().unwrap(), "{line}");
        let mut lines = self.lines.lock().unwrap();
        lines.push_back(line.to_string());
        while lines.len() > TAIL_LINES {
            lines.pop_front();
        }
        *self.count.lock().unwrap() += 1;
    }
}

fn pump(reader: impl Read + Send + 'static, sink: Sink) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            match line {
                Ok(l) => sink.line(&l),
                Err(_) => break,
            }
        }
    })
}

/// Signals the child's whole process group, so a tool and anything it spawned
/// (and children like `sleep` under `sh -c`) all receive it.
fn signal_group(child: &Child, sig: libc::c_int) {
    unsafe {
        libc::kill(-(child.id() as libc::pid_t), sig);
    }
}

fn run_stages(
    stages: &[Vec<String>],
    timed: bool,
    secs: u64,
    stop: &AtomicBool,
    sink: &Sink,
) -> RunState {
    use std::os::unix::process::CommandExt;
    let mut last = None;
    for (i, argv) in stages.iter().enumerate() {
        if i > 0 {
            // A stop request ends the capture stage; post-processing still runs
            // unless the analyst stops it again.
            stop.store(false, Ordering::SeqCst);
        }
        sink.line(&format!("### {} $ {}", util::now_rfc3339(), argv.join(" ")));
        let mut child = match Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("LC_ALL", "C")
            .process_group(0)
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return RunState::Failed(format!("{}: {e}", argv[0])),
        };
        let out = pump(child.stdout.take().unwrap(), sink.clone());
        let err = pump(child.stderr.take().unwrap(), sink.clone());
        // Only the first stage is the timed capture; later stages post-process it.
        let deadline = Instant::now()
            + if timed && i == 0 {
                Duration::from_secs(secs + 10)
            } else {
                Duration::from_secs(900)
            };
        let interrupt_at = (timed && i == 0).then(|| Instant::now() + Duration::from_secs(secs));
        // On stop we escalate: SIGINT (lets strace/perf/tcpdump flush summaries),
        // then SIGTERM, then SIGKILL for processes that ignore the gentler signals.
        let mut stop_since: Option<Instant> = None;
        let mut last_signal = 0;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status.code(),
                Ok(None) => {}
                Err(e) => return RunState::Failed(e.to_string()),
            }
            let now = Instant::now();
            let want_stop = stop.load(Ordering::SeqCst)
                || interrupt_at.is_some_and(|t| now >= t)
                || now > deadline;
            if want_stop && stop_since.is_none() {
                stop_since = Some(now);
            }
            if let Some(t0) = stop_since {
                let waited = now.duration_since(t0).as_secs();
                let stage = if waited >= 6 {
                    libc::SIGKILL
                } else if waited >= 3 {
                    libc::SIGTERM
                } else {
                    libc::SIGINT
                };
                if stage != last_signal {
                    signal_group(&child, stage);
                    last_signal = stage;
                }
            }
            thread::sleep(Duration::from_millis(100));
        };
        let _ = out.join();
        let _ = err.join();
        sink.line(&format!(
            "### {} exit status {}",
            util::now_rfc3339(),
            status.map_or("signal".into(), |c| c.to_string())
        ));
        last = status;
        if i > 0 && stop.load(Ordering::SeqCst) {
            break;
        }
    }
    RunState::Finished(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo;

    #[test]
    fn every_profile_builds_commands() {
        let snap = demo::snapshot(0);
        for p in PROFILES {
            let (stages, _) = commands(p, 4242, 5, Path::new("/case/trace"), "T", &snap).unwrap();
            assert!(!stages.is_empty());
            assert_eq!(stages[0][0], p.tool, "{}", p.id);
        }
    }

    #[test]
    fn checklist_lists_missing_packages_once() {
        let text = checklist(
            |t| (t == "strace").then(|| PathBuf::from("/usr/bin/strace")),
            false,
            Some(1),
        );
        assert!(text.contains("ok  /usr/bin/strace"), "{text}");
        assert!(
            text.contains("Syscalls · everything, file access, network"),
            "{text}"
        );
        assert!(
            text.contains("ptrace_scope  1 restricted — ptrace/pause captures need sudo"),
            "{text}"
        );
        assert!(
            text.contains("sudo apt install ltrace linux-perf bpftrace tcpdump gdb\n"),
            "{text}"
        );

        let all = checklist(|t| Some(PathBuf::from(t)), true, None);
        assert!(all.contains("All capture tools are installed."), "{all}");
        assert!(
            !all.contains("MISSING") && !all.contains("ptrace_scope"),
            "{all}"
        );
    }

    #[test]
    fn port_filter_from_sockets() {
        let f = port_filter(&demo::snapshot(0)).unwrap();
        assert!(f.contains("port 8080"), "{f}");
    }

    #[test]
    fn runs_and_interrupts_a_command() {
        let dir = std::env::temp_dir().join(format!("piddigger-run-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let profile = Profile {
            id: "t",
            title: "t",
            tool: "sh",
            package: "",
            impact: Impact::Observe,
            timed: true,
            about: "",
        };
        let argv = vec![vec![
            "sh".into(),
            "-c".into(),
            "echo hello; sleep 30".into(),
        ]];
        let run = Run::start(profile, argv, 1, dir.join("t.log"), vec![]).unwrap();
        let t = Instant::now();
        while run.is_running() && t.elapsed() < Duration::from_secs(10) {
            thread::sleep(Duration::from_millis(50));
        }
        assert!(!run.is_running());
        assert!(run.tail(10).iter().any(|l| l == "hello"));
        assert!(t.elapsed() < Duration::from_secs(8));
        let _ = fs::remove_dir_all(&dir);
    }
}
