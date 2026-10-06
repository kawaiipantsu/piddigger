//! piddigger — live PID forensics for blue teams.
//!
//! A read-only `/proc` collector with a terminal UI, triage heuristics, opt-in
//! tracing and a hashed evidence case. Built by Kawaiipantsu for THUGS(red).

mod activity;
mod app;
mod collect;
mod demo;
mod evidence;
mod findings;
mod model;
mod procfs;
mod tools;
mod ui;
mod util;

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use ratatui::crossterm::event::{self, Event};
use ratatui::crossterm::{execute, terminal};

use app::App;
use ui::theme::{Theme, ThemeKind};

/// Live PID forensics for blue teams — a read-only /proc investigator.
#[derive(Parser, Debug)]
#[command(
    name = "piddigger",
    version,
    about = "Live PID forensics for blue teams — by Kawaiipantsu / THUGS(red)",
    long_about = None,
)]
struct Cli {
    /// PID to investigate. Omit to open the process picker.
    pid: Option<i32>,

    /// Color theme: thugsred, midnight, carbon, dracula, twilight, daylight.
    #[arg(long, default_value = "thugsred")]
    theme: String,

    /// Refresh interval in milliseconds (250–10000).
    #[arg(long, default_value_t = 1000)]
    interval: u64,

    /// Use ASCII borders and markers instead of Unicode box drawing.
    #[arg(long)]
    ascii: bool,

    /// Disable Nerd Font icons (use ASCII labels).
    #[arg(long)]
    no_icons: bool,

    /// Directory to hold evidence cases.
    #[arg(long, default_value = ".")]
    case_dir: PathBuf,

    /// Run against a built-in synthetic process (no root, no live /proc).
    #[arg(long)]
    demo: bool,

    /// Print one JSON snapshot to stdout and exit (no TUI).
    #[arg(long)]
    json: bool,

    /// Print a plain-text triage report to stdout and exit (no TUI).
    #[arg(long)]
    report: bool,
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("piddigger: {e}");
        std::process::exit(1);
    }
}

fn resolve_theme(name: &str) -> ThemeKind {
    ThemeKind::from_name(name).unwrap_or_else(|| {
        eprintln!("piddigger: unknown theme '{name}', using thugsred");
        ThemeKind::ThugsRed
    })
}

fn run(cli: Cli) -> io::Result<()> {
    let interval = cli.interval.clamp(250, 10_000);

    // Non-interactive output modes.
    if cli.json || cli.report {
        let pid = cli
            .pid
            .ok_or_else(|| io::Error::other("a PID is required for --json/--report"))?;
        let snap = if cli.demo {
            demo::snapshot(0)
        } else {
            collect::Collector::new(pid).collect()
        };
        if snap.exited && !cli.demo {
            return Err(io::Error::other(format!("pid {pid} is not running")));
        }
        let mut out = io::stdout().lock();
        if cli.json {
            serde_json::to_writer_pretty(&mut out, &snap).map_err(io::Error::other)?;
            writeln!(out)?;
        } else {
            let f = findings::analyze(&snap);
            write!(out, "{}", evidence::findings_text(&snap, &f))?;
        }
        return Ok(());
    }

    // A real terminal is required for the TUI.
    if !io::stdout().is_terminal() {
        return Err(io::Error::other(
            "stdout is not a terminal — use --json or --report for non-interactive output",
        ));
    }

    let nerd = !cli.no_icons;
    let theme = Theme::new(resolve_theme(&cli.theme), nerd, cli.ascii);
    let case_dir = cli.case_dir.clone();

    // Resolve the target PID: argument, or the picker, or demo.
    let pid = match (cli.pid, cli.demo) {
        (Some(p), _) => p,
        (None, true) => 0,
        (None, false) => std::process::id() as i32, // placeholder; picker opens on launch
    };

    let mut app = App::new(pid, theme, interval, cli.demo, case_dir);
    if cli.pid.is_none() && !cli.demo {
        app.open_picker();
        app.toast(app::ToastKind::Info, "select a process to investigate");
    } else if !cli.demo && app.snap.exited {
        return Err(io::Error::other(format!("pid {pid} is not running")));
    }

    let mut term = TerminalGuard::enter()?;
    let res = event_loop(&mut app, &mut term.terminal);
    term.leave()?;

    // Close the case after the terminal is restored so the summary is visible.
    if let Some(case) = app.case.as_mut() {
        case.close();
        println!("piddigger: evidence case written to {}", case.dir.display());
        println!("           verify with: sha256sum -c SHA256SUMS");
    }
    res
}

fn event_loop(app: &mut App, terminal: &mut ratatui::DefaultTerminal) -> io::Result<()> {
    while !app.should_quit {
        terminal.draw(|f| ui::draw(f, app))?;
        // Poll briefly so live refresh and trace output stay responsive.
        let timeout = Duration::from_millis(120);
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) if key.kind == event::KeyEventKind::Press => {
                    ui::handle_key(app, key)
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
        app.on_tick();
    }
    Ok(())
}

/// RAII guard that enables and restores raw mode and the alternate screen.
struct TerminalGuard {
    terminal: ratatui::DefaultTerminal,
}

impl TerminalGuard {
    fn enter() -> io::Result<TerminalGuard> {
        terminal::enable_raw_mode()?;
        let mut out = io::stdout();
        execute!(
            out,
            terminal::EnterAlternateScreen,
            ratatui::crossterm::cursor::Hide
        )?;
        let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
        let terminal = ratatui::Terminal::new(backend)?;
        Ok(TerminalGuard { terminal })
    }

    fn leave(&mut self) -> io::Result<()> {
        terminal::disable_raw_mode()?;
        execute!(
            io::stdout(),
            terminal::LeaveAlternateScreen,
            ratatui::crossterm::cursor::Show
        )?;
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            terminal::LeaveAlternateScreen,
            ratatui::crossterm::cursor::Show
        );
    }
}
