//! Application state: the model behind the TUI, independent of rendering.

use std::collections::VecDeque;
use std::path::PathBuf;

use crate::activity::{self, Event};
use crate::collect::Collector;
use crate::evidence::{Case, PreserveOptions};
use crate::findings::{self, Finding};
use crate::model::{ProcRow, Snapshot};
use crate::tools::{self, Profile, Run};
use crate::ui::theme::{Theme, ThemeKind};
use crate::util;

/// Primary views, in tab order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Tree,
    Files,
    Network,
    Memory,
    Security,
    Threads,
    Environment,
    Activity,
    Findings,
    Trace,
    Evidence,
}

impl Tab {
    pub const ALL: [Tab; 12] = [
        Tab::Overview,
        Tab::Tree,
        Tab::Files,
        Tab::Network,
        Tab::Memory,
        Tab::Security,
        Tab::Threads,
        Tab::Environment,
        Tab::Activity,
        Tab::Findings,
        Tab::Trace,
        Tab::Evidence,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Tree => "Tree",
            Tab::Files => "Files",
            Tab::Network => "Network",
            Tab::Memory => "Memory",
            Tab::Security => "Security",
            Tab::Threads => "Threads",
            Tab::Environment => "Environ",
            Tab::Activity => "Activity",
            Tab::Findings => "Findings",
            Tab::Trace => "Trace",
            Tab::Evidence => "Evidence",
        }
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

/// A transient status-bar message with a severity tint.
#[derive(Debug, Clone)]
pub struct Toast {
    pub text: String,
    pub kind: ToastKind,
    pub at: std::time::Instant,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ToastKind {
    Info,
    Good,
    Warn,
    Error,
}

/// Which modal overlay, if any, is open.
#[derive(Debug, Clone, PartialEq)]
pub enum Overlay {
    None,
    Help,
    ProcessPicker,
    ThemePicker,
    TraceMenu,
    /// Confirm an action; carries the pending action.
    Confirm(PendingAction),
}

#[derive(Debug, Clone, PartialEq)]
pub enum PendingAction {
    RunProfile(usize),
    Snapshot,
    RecoverFd(i32, String),
    Quit,
}

pub struct App {
    pub collector: Collector,
    pub snap: Snapshot,
    pub prev_snap: Option<Snapshot>,
    pub findings: Vec<Finding>,
    pub timeline: VecDeque<Event>,
    pub theme: Theme,
    pub tab: Tab,
    pub overlay: Overlay,
    pub paused: bool,
    pub refresh_ms: u64,
    pub demo_mode: bool,
    pub demo_tick: u64,
    pub should_quit: bool,
    pub scroll: [usize; 12],
    pub selected: usize,
    pub toast: Option<Toast>,
    pub case: Option<Case>,
    pub case_root: PathBuf,
    pub runs: Vec<Run>,
    pub active_run: Option<usize>,
    pub trace_cursor: usize,
    pub trace_secs: u64,
    pub picker_rows: Vec<ProcRow>,
    pub picker_filter: String,
    pub picker_cursor: usize,
    pub show_env_values: bool,
    pub show_kernel_threads: bool,
    pub preserve_opts: PreserveOptions,
    pub rss_history: VecDeque<u64>,
    pub cpu_history: VecDeque<u64>,
    pub last_cpu_ticks: Option<(u64, f64)>,
    pub refresh_count: u64,
    pub last_refresh: std::time::Instant,
}

pub const REFRESH_STEPS: [u64; 7] = [250, 500, 1000, 2000, 3000, 5000, 10000];
const TIMELINE_CAP: usize = 500;
const HISTORY_CAP: usize = 120;

impl App {
    pub fn new(
        pid: i32,
        theme: Theme,
        refresh_ms: u64,
        demo_mode: bool,
        case_root: PathBuf,
    ) -> App {
        let mut collector = Collector::new(pid);
        let snap = if demo_mode {
            crate::demo::snapshot(0)
        } else {
            collector.collect()
        };
        let findings = findings::analyze(&snap);
        let mut app = App {
            collector,
            findings,
            prev_snap: None,
            timeline: VecDeque::new(),
            theme,
            tab: Tab::Overview,
            overlay: Overlay::None,
            paused: false,
            refresh_ms,
            demo_mode,
            demo_tick: 0,
            should_quit: false,
            scroll: [0; 12],
            selected: 0,
            toast: None,
            case: None,
            case_root,
            runs: Vec::new(),
            active_run: None,
            trace_cursor: 0,
            trace_secs: 10,
            picker_rows: Vec::new(),
            picker_filter: String::new(),
            picker_cursor: 0,
            show_env_values: true,
            show_kernel_threads: false,
            preserve_opts: PreserveOptions::default(),
            rss_history: VecDeque::new(),
            cpu_history: VecDeque::new(),
            last_cpu_ticks: None,
            refresh_count: 0,
            last_refresh: std::time::Instant::now(),
            snap,
        };
        app.record_history();
        app
    }

    pub fn pid(&self) -> i32 {
        self.snap.ident.pid
    }

    pub fn toast(&mut self, kind: ToastKind, text: impl Into<String>) {
        self.toast = Some(Toast {
            text: text.into(),
            kind,
            at: std::time::Instant::now(),
        });
    }

    pub fn refresh_due(&self) -> bool {
        !self.paused && self.last_refresh.elapsed().as_millis() as u64 >= self.refresh_ms
    }

    /// Collects a fresh snapshot and folds the change into the timeline, findings and history.
    pub fn refresh(&mut self) {
        let new = if self.demo_mode {
            self.demo_tick = self.demo_tick.wrapping_add(1);
            crate::demo::snapshot(self.demo_tick % 2)
        } else {
            self.collector.collect()
        };
        let events = activity::diff(&self.snap, &new);
        for e in events {
            self.timeline.push_front(e);
        }
        while self.timeline.len() > TIMELINE_CAP {
            self.timeline.pop_back();
        }
        self.prev_snap = Some(std::mem::replace(&mut self.snap, new));
        self.findings = findings::analyze(&self.snap);
        self.record_history();
        self.refresh_count += 1;
        self.last_refresh = std::time::Instant::now();
        if self.snap.exited {
            self.paused = true;
        }
    }

    fn record_history(&mut self) {
        let rss = self.snap.mem.vm_rss_kb;
        self.rss_history.push_back(rss);
        while self.rss_history.len() > HISTORY_CAP {
            self.rss_history.pop_front();
        }
        // CPU ratio from the delta of used ticks over wall-clock ticks.
        let total_ticks = self.snap.ident.utime_ticks + self.snap.ident.stime_ticks;
        let now = crate::collect::unix_now();
        if let Some((prev_ticks, prev_t)) = self.last_cpu_ticks {
            let dt = (now - prev_t).max(0.001);
            let clk = self.snap.host.clk_tck.max(1) as f64;
            let busy = (total_ticks.saturating_sub(prev_ticks)) as f64 / clk;
            let pct = ((busy / dt) * 100.0).clamp(0.0, 100.0 * self.snap.host.num_cpus as f64);
            self.cpu_history.push_back(pct as u64);
            while self.cpu_history.len() > HISTORY_CAP {
                self.cpu_history.pop_front();
            }
        }
        self.last_cpu_ticks = Some((total_ticks, now));
    }

    pub fn cpu_percent(&self) -> f64 {
        self.cpu_history.back().copied().unwrap_or(0) as f64
    }

    pub fn next_tab(&mut self) {
        let i = self.tab.index();
        self.tab = Tab::ALL[(i + 1) % Tab::ALL.len()];
        self.selected = 0;
    }
    pub fn prev_tab(&mut self) {
        let i = self.tab.index();
        self.tab = Tab::ALL[(i + Tab::ALL.len() - 1) % Tab::ALL.len()];
        self.selected = 0;
    }
    pub fn set_tab(&mut self, tab: Tab) {
        self.tab = tab;
        self.selected = 0;
    }

    pub fn scroll_mut(&mut self) -> &mut usize {
        &mut self.scroll[self.tab.index()]
    }

    pub fn cycle_theme(&mut self) {
        let kind = self.theme.kind.next();
        self.theme = Theme::new(kind, self.theme.nerd, self.theme.ascii);
        self.toast(
            ToastKind::Info,
            format!("theme: {} ({})", kind.name(), kind.tone()),
        );
    }
    pub fn set_theme(&mut self, kind: ThemeKind) {
        self.theme = Theme::new(kind, self.theme.nerd, self.theme.ascii);
    }

    pub fn adjust_refresh(&mut self, faster: bool) {
        let i = REFRESH_STEPS
            .iter()
            .position(|s| *s == self.refresh_ms)
            .unwrap_or(1);
        let ni = if faster {
            i.saturating_sub(1)
        } else {
            (i + 1).min(REFRESH_STEPS.len() - 1)
        };
        self.refresh_ms = REFRESH_STEPS[ni];
        self.toast(ToastKind::Info, format!("refresh: {} ms", self.refresh_ms));
    }

    // --- Evidence --------------------------------------------------------------

    /// Ensures a case folder exists, creating one on first use.
    pub fn ensure_case(&mut self) -> Result<(), String> {
        if self.case.is_some() {
            return Ok(());
        }
        match Case::open(&self.case_root, &self.snap) {
            Ok(case) => {
                self.toast(ToastKind::Good, format!("case opened: {}", case.id));
                self.case = Some(case);
                Ok(())
            }
            Err(e) => {
                let msg = format!("could not open case: {e}");
                self.toast(ToastKind::Error, msg.clone());
                Err(msg)
            }
        }
    }

    pub fn do_snapshot(&mut self) {
        if self.demo_mode {
            self.toast(ToastKind::Warn, "snapshots are disabled in demo mode");
            return;
        }
        if self.ensure_case().is_err() {
            return;
        }
        let snap = self.snap.clone();
        let findings = self.findings.clone();
        let timeline: Vec<Event> = self.timeline.iter().cloned().collect();
        let opts = self.preserve_opts;
        let case = self.case.as_mut().unwrap();
        match case.preserve(&snap, &findings, &timeline, opts) {
            Ok(sum) => {
                let msg = if sum.skipped.is_empty() {
                    format!(
                        "snapshot {} · {} files · {}",
                        sum.dir,
                        sum.files,
                        util::human_bytes(sum.bytes)
                    )
                } else {
                    format!(
                        "snapshot {} · {} files · {} skipped",
                        sum.dir,
                        sum.files,
                        sum.skipped.len()
                    )
                };
                self.toast(ToastKind::Good, msg);
            }
            Err(e) => self.toast(ToastKind::Error, format!("snapshot failed: {e}")),
        }
    }

    pub fn verify_case(&mut self) {
        let Some(case) = self.case.as_mut() else {
            self.toast(ToastKind::Warn, "no case yet — press 's' to snapshot first");
            return;
        };
        let results = case.verify();
        let bad = results
            .iter()
            .filter(|(_, r)| !matches!(r, Ok(true)))
            .count();
        if bad == 0 {
            self.toast(
                ToastKind::Good,
                format!("verified {} artifacts — all hashes match", results.len()),
            );
        } else {
            self.toast(
                ToastKind::Error,
                format!("{bad}/{} artifacts FAILED verification", results.len()),
            );
        }
    }

    // --- Tracing ---------------------------------------------------------------

    pub fn profile_available(&self, p: &Profile) -> bool {
        tools::find_in_path(p.tool).is_some()
    }

    pub fn start_profile(&mut self, idx: usize) {
        if self.demo_mode {
            self.toast(ToastKind::Warn, "tracing is disabled in demo mode");
            return;
        }
        let Some(profile) = tools::PROFILES.get(idx).copied() else {
            return;
        };
        if tools::find_in_path(profile.tool).is_none() {
            self.toast(
                ToastKind::Error,
                format!(
                    "{} not installed — apt install {}",
                    profile.tool, profile.package
                ),
            );
            return;
        }
        if self.ensure_case().is_err() {
            return;
        }
        let pid = self.pid();
        let snap = self.snap.clone();
        let stamp = util::now_compact();
        let case = self.case.as_mut().unwrap();
        let trace_dir = match case.subdir("trace") {
            Ok(d) => d,
            Err(e) => {
                self.toast(ToastKind::Error, format!("trace dir: {e}"));
                return;
            }
        };
        let (argv, artifacts) =
            match tools::commands(&profile, pid, self.trace_secs, &trace_dir, &stamp, &snap) {
                Ok(v) => v,
                Err(e) => {
                    self.toast(ToastKind::Error, e);
                    return;
                }
            };
        let log_path = trace_dir.join(format!("{}-{stamp}.log", profile.id));
        case.log(
            "TRACE",
            &format!(
                "start {} impact={} secs={} argv={:?}",
                profile.id,
                profile.impact.label(),
                self.trace_secs,
                argv
            ),
        );
        match Run::start(profile, argv, self.trace_secs, log_path, artifacts) {
            Ok(run) => {
                self.active_run = Some(self.runs.len());
                self.runs.push(run);
                self.tab = Tab::Trace;
                self.toast(
                    ToastKind::Good,
                    format!("{} started ({})", profile.title, profile.impact.label()),
                );
            }
            Err(e) => self.toast(ToastKind::Error, format!("could not start: {e}")),
        }
    }

    pub fn stop_active_run(&mut self) {
        if let Some(run) = self.active_run.and_then(|i| self.runs.get(i)) {
            run.stop();
            self.toast(ToastKind::Info, "stopping trace…");
        }
    }

    /// Hashes finished runs' output into the case exactly once.
    pub fn reap_runs(&mut self) {
        let mut messages = Vec::new();
        if let Some(case) = self.case.as_mut() {
            for run in self.runs.iter_mut() {
                if run.registered || run.is_running() {
                    continue;
                }
                run.registered = true;
                let _ = case.register(&run.log_path, &format!("{} trace log", run.profile.id));
                for art in &run.artifacts {
                    if art.exists() {
                        match case.register(art, &format!("{} artifact", run.profile.id)) {
                            Ok(e) => messages.push((
                                ToastKind::Good,
                                format!("captured {} ({})", e.path, util::human_bytes(e.size)),
                            )),
                            Err(e) => {
                                messages.push((ToastKind::Error, format!("register failed: {e}")))
                            }
                        }
                    }
                }
                if let crate::tools::RunState::Failed(e) = run.state() {
                    messages.push((ToastKind::Error, format!("{} failed: {e}", run.profile.id)));
                }
            }
        }
        for (kind, msg) in messages {
            self.toast(kind, msg);
        }
    }

    pub fn any_run_active(&self) -> bool {
        self.runs.iter().any(|r| r.is_running())
    }

    // --- Process picker --------------------------------------------------------

    pub fn open_picker(&mut self) {
        self.picker_rows = self.collector.list_processes();
        self.picker_rows
            .sort_by(|a, b| b.rss_kb.cmp(&a.rss_kb).then(a.pid.cmp(&b.pid)));
        self.picker_filter.clear();
        self.picker_cursor = 0;
        self.overlay = Overlay::ProcessPicker;
    }

    pub fn filtered_picker(&self) -> Vec<&ProcRow> {
        let f = self.picker_filter.to_lowercase();
        self.picker_rows
            .iter()
            .filter(|r| self.show_kernel_threads || !r.kernel_thread)
            .filter(|r| {
                f.is_empty()
                    || r.comm.to_lowercase().contains(&f)
                    || r.cmdline.to_lowercase().contains(&f)
                    || r.pid.to_string().contains(&f)
                    || r.user.to_lowercase().contains(&f)
            })
            .collect()
    }

    pub fn attach_to(&mut self, pid: i32) {
        if pid == self.pid() && self.case.is_none() {
            self.overlay = Overlay::None;
            return;
        }
        self.collector = Collector::new(pid);
        if !crate::collect::pid_exists(pid) {
            self.toast(ToastKind::Error, format!("pid {pid} does not exist"));
            return;
        }
        self.snap = self.collector.collect();
        self.findings = findings::analyze(&self.snap);
        self.prev_snap = None;
        self.timeline.clear();
        self.rss_history.clear();
        self.cpu_history.clear();
        self.last_cpu_ticks = None;
        self.case = None;
        self.runs.clear();
        self.active_run = None;
        self.scroll = [0; 12];
        self.paused = false;
        self.overlay = Overlay::None;
        self.tab = Tab::Overview;
        self.record_history();
        self.toast(
            ToastKind::Good,
            format!("attached to pid {pid} ({})", self.snap.ident.comm),
        );
    }

    pub fn confirm(&mut self, action: PendingAction) {
        self.overlay = Overlay::None;
        match action {
            PendingAction::RunProfile(i) => self.start_profile(i),
            PendingAction::Snapshot => self.do_snapshot(),
            PendingAction::RecoverFd(fd, target) => self.recover_fd(fd, &target),
            PendingAction::Quit => self.should_quit = true,
        }
    }

    pub fn recover_fd(&mut self, fd: i32, target: &str) {
        if self.demo_mode {
            self.toast(ToastKind::Warn, "recovery is disabled in demo mode");
            return;
        }
        if self.ensure_case().is_err() {
            return;
        }
        let pid = self.pid();
        let max = self.preserve_opts.max_copy_bytes;
        let case = self.case.as_mut().unwrap();
        match case.recover_fd(pid, fd, target, max) {
            Ok((e, trunc)) => {
                let msg = format!(
                    "recovered fd {fd} → {} ({}{})",
                    e.path,
                    util::human_bytes(e.size),
                    if trunc { ", truncated" } else { "" }
                );
                self.toast(ToastKind::Good, msg);
            }
            Err(e) => self.toast(ToastKind::Error, format!("recover fd {fd} failed: {e}")),
        }
    }

    pub fn on_tick(&mut self) {
        if self.refresh_due() {
            self.refresh();
        }
        self.reap_runs();
        if let Some(t) = &self.toast {
            if t.at.elapsed().as_secs() >= 6 {
                self.toast = None;
            }
        }
    }
}
