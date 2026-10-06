//! Modal overlays: help, process picker, theme picker, trace menu, confirm.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table};
use ratatui::Frame;

use super::theme::Glyph;
use super::widgets::{centered, centered_pct, panel};
use crate::app::{App, PendingAction};
use crate::tools::{Impact, PROFILES};

fn modal(f: &mut Frame, app: &App, area: Rect, title: &str, icon: Glyph) -> Rect {
    let theme = &app.theme;
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(theme.border_type())
        .border_set(theme.border_set())
        .border_style(theme.border_focus())
        .title_top(Line::from(vec![
            Span::raw(" "),
            Span::styled(theme.g(icon), theme.accent()),
            Span::styled(format!(" {title} "), theme.title()),
        ]))
        .style(theme.panel());
    let inner = block.inner(area);
    f.render_widget(block, area);
    inner
}

pub fn help(f: &mut Frame, app: &App, screen: Rect) {
    let theme = &app.theme;
    let area = centered_pct(screen, 80, 90, 78, 32);
    let inner = modal(f, app, area, "piddigger — help", Glyph::Help);
    let key = |k: &str| Span::styled(format!("{k:<12}"), theme.accent());
    let desc = |d: &'static str| Span::styled(d, Style::default().fg(theme.palette.fg));
    let head = |t: &'static str| Line::from(Span::styled(t, theme.accent()));
    let lines = vec![
        Line::from(vec![
            Span::styled("Live PID forensics for blue teams — ", theme.dim()),
            Span::styled(
                "read-only by default.",
                Style::default().fg(theme.palette.good),
            ),
        ]),
        Line::from(""),
        head("Navigation"),
        Line::from(vec![
            Span::raw("  "),
            key("Tab / ←→"),
            desc("switch view        "),
            key("1-9,0,r,c"),
            desc("jump to view"),
        ]),
        Line::from(vec![
            Span::raw("  "),
            key("↑↓ j k"),
            desc("scroll             "),
            key("PgUp/PgDn"),
            desc("scroll a page"),
        ]),
        Line::from(vec![
            Span::raw("  "),
            key("p"),
            desc("process picker (attach to another PID)"),
        ]),
        Line::from(""),
        head("Collection & tracing"),
        Line::from(vec![
            Span::raw("  "),
            key("Space"),
            desc("pause/resume live refresh    "),
            key("g"),
            desc("refresh now"),
        ]),
        Line::from(vec![
            Span::raw("  "),
            key("+ / -"),
            desc("faster / slower refresh      "),
            key("R"),
            desc("trace menu"),
        ]),
        Line::from(vec![
            Span::raw("  "),
            key("x"),
            desc("stop the active trace"),
        ]),
        Line::from(""),
        head("Evidence"),
        Line::from(vec![
            Span::raw("  "),
            key("s"),
            desc("snapshot /proc + exe + deleted files into the case"),
        ]),
        Line::from(vec![
            Span::raw("  "),
            key("Enter"),
            desc("on Files: recover the selected deleted-but-open file"),
        ]),
        Line::from(vec![
            Span::raw("  "),
            key("v"),
            desc("verify every artifact's SHA-256"),
        ]),
        Line::from(""),
        head("Appearance"),
        Line::from(vec![
            Span::raw("  "),
            key("t"),
            desc("cycle theme                  "),
            key("T"),
            desc("theme picker"),
        ]),
        Line::from(vec![
            Span::raw("  "),
            key("n"),
            desc("show/hide environment values"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Impact levels: ", theme.dim()),
            Span::styled("observe", Style::default().fg(theme.palette.good)),
            Span::styled(" (kernel), ", theme.dim()),
            Span::styled("ptrace", Style::default().fg(theme.palette.warn)),
            Span::styled(" (slows+visible), ", theme.dim()),
            Span::styled("pause", Style::default().fg(theme.palette.crit)),
            Span::styled(" (stops target)", theme.dim()),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Findings are leads, not verdicts. Preserve before you contain.",
            theme.faint(),
        )),
        Line::from(Span::styled(
            "  THUGS(red) · https://thugs.red · press any key to close",
            theme.faint(),
        )),
    ];
    f.render_widget(Paragraph::new(lines).style(theme.panel()), inner);
}

pub fn process_picker(f: &mut Frame, app: &App, screen: Rect) {
    let theme = &app.theme;
    let area = centered_pct(screen, 90, 85, 120, 40);
    let title = format!("Attach to process — filter: '{}'", app.picker_filter);
    let inner = modal(f, app, area, &title, Glyph::Search);
    let [list, hint] = Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(inner);
    let rows = app.filtered_picker();
    let visible = list.height.saturating_sub(1) as usize;
    let start = app.picker_cursor.saturating_sub(visible.saturating_sub(1));
    let header = Row::new(["", "PID", "PPID", "USER", "STATE", "RSS", "THR", "COMMAND"])
        .style(theme.header());
    let body = rows
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(i, r)| {
            let selected = i == app.picker_cursor;
            let marker = if selected { "▶" } else { " " };
            let base = if r.exe_deleted {
                Style::default().fg(theme.palette.crit)
            } else if r.kernel_thread {
                theme.faint()
            } else {
                Style::default().fg(theme.palette.fg)
            };
            let style = if selected { theme.selection() } else { base };
            Row::new([
                Cell::from(marker),
                Cell::from(r.pid.to_string()),
                Cell::from(r.ppid.to_string()),
                Cell::from(crate::util::truncate(&r.user, 10)),
                Cell::from(r.state.clone()),
                Cell::from(crate::util::human_kb(r.rss_kb)),
                Cell::from(r.threads.to_string()),
                Cell::from(crate::util::truncate(&r.cmdline, 60)),
            ])
            .style(style)
        });
    let table = Table::new(
        body,
        [
            Constraint::Length(1),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(11),
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Length(4),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .style(theme.panel());
    f.render_widget(table, list);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!(" {} match ", rows.len()), theme.dim()),
            Span::styled("· type to filter · ", theme.faint()),
            Span::styled("↑↓", theme.accent()),
            Span::styled(" move · ", theme.faint()),
            Span::styled("Enter", theme.accent()),
            Span::styled(" attach · ", theme.faint()),
            Span::styled("Esc", theme.accent()),
            Span::styled(" cancel", theme.faint()),
        ]))
        .style(theme.panel()),
        hint,
    );
}

pub fn theme_picker(f: &mut Frame, app: &App, screen: Rect) {
    let theme = &app.theme;
    let area = centered(screen, 48, 12);
    let inner = modal(f, app, area, "Theme", Glyph::Dot);
    let mut lines = Vec::new();
    for (i, kind) in super::theme::ThemeKind::ALL.iter().enumerate() {
        let active = *kind == theme.kind;
        let marker = if active { "▶ " } else { "  " };
        let style = if active {
            theme.selection()
        } else {
            Style::default().fg(theme.palette.fg)
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {marker}{}. ", i + 1), theme.accent()),
            Span::styled(format!("{:<12}", kind.name()), style),
            Span::styled(format!("({})", kind.tone()), theme.faint()),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " ↑↓ preview · 1-6 pick · Esc close",
        theme.faint(),
    )));
    f.render_widget(Paragraph::new(lines).style(theme.panel()), inner);
}

pub fn trace_menu(f: &mut Frame, app: &App, screen: Rect) {
    let theme = &app.theme;
    let area = centered_pct(screen, 92, 90, 110, 34);
    let title = format!(
        "Trace & capture — duration {}s  (+/- to change)",
        app.trace_secs
    );
    let inner = modal(f, app, area, &title, Glyph::Trace);
    let [list, detail] = Layout::vertical([Constraint::Min(8), Constraint::Length(6)]).areas(inner);
    let header = Row::new(["", "CAPTURE", "TOOL", "IMPACT", "STATUS"]).style(theme.header());
    let rows = PROFILES.iter().enumerate().map(|(i, p)| {
        let selected = i == app.trace_cursor;
        let available = app.profile_available(p);
        let (impact_txt, impact_color) = match p.impact {
            Impact::Observe => ("observe", theme.palette.good),
            Impact::Ptrace => ("ptrace", theme.palette.warn),
            Impact::Pause => ("pause", theme.palette.crit),
        };
        let status = if available {
            Span::styled("ready", Style::default().fg(theme.palette.good))
        } else {
            Span::styled(format!("apt install {}", p.package), theme.faint())
        };
        let marker = if selected { "▶" } else { " " };
        let name_style = if selected {
            theme.selection()
        } else if available {
            Style::default().fg(theme.palette.fg)
        } else {
            theme.faint()
        };
        Row::new(vec![
            Cell::from(marker),
            Cell::from(Span::styled(p.title, name_style)),
            Cell::from(p.tool),
            Cell::from(Span::styled(
                impact_txt,
                Style::default()
                    .fg(impact_color)
                    .add_modifier(Modifier::BOLD),
            )),
            Cell::from(status),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Min(26),
            Constraint::Length(10),
            Constraint::Length(9),
            Constraint::Length(24),
        ],
    )
    .header(header)
    .style(theme.panel());
    f.render_widget(table, list);

    let sel = &PROFILES[app.trace_cursor.min(PROFILES.len() - 1)];
    let block = panel(
        theme,
        Line::from(Span::styled(" what it does ", theme.title())),
        false,
    );
    let dinner = block.inner(detail);
    f.render_widget(block, detail);
    let lines = vec![
        Line::from(Span::styled(
            sel.about,
            Style::default().fg(theme.palette.fg),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                sel.impact.label().to_uppercase(),
                Style::default()
                    .fg(match sel.impact {
                        Impact::Observe => theme.palette.good,
                        Impact::Ptrace => theme.palette.warn,
                        Impact::Pause => theme.palette.crit,
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" — {}", sel.impact.warning()), theme.dim()),
        ]),
        Line::from(vec![
            Span::styled("Enter", theme.accent()),
            Span::styled(" run · ", theme.faint()),
            Span::styled("↑↓", theme.accent()),
            Span::styled(" select · ", theme.faint()),
            Span::styled("Esc", theme.accent()),
            Span::styled(" cancel · output is hashed into the case", theme.faint()),
        ]),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .style(theme.panel())
            .wrap(ratatui::widgets::Wrap { trim: true }),
        dinner,
    );
}

pub fn confirm(f: &mut Frame, app: &App, screen: Rect, action: &PendingAction) {
    let theme = &app.theme;
    let (title, body, warn) = match action {
        PendingAction::RunProfile(i) => {
            let p = &PROFILES[(*i).min(PROFILES.len() - 1)];
            let mut warn = p.impact.warning().to_string();
            // Yama ptrace_scope can block attach-based tools for non-root users.
            if matches!(p.impact, Impact::Ptrace | Impact::Pause) {
                match crate::tools::ptrace_scope() {
                    Some(scope @ 1..) if app.snap.host.collector_uid != 0 => {
                        warn = format!(
                            "{warn}  ⚠ kernel yama/ptrace_scope={scope}: attaching as non-root will likely fail — run piddigger with sudo."
                        );
                    }
                    _ => {}
                }
            }
            (
                format!("Run {}?", p.title),
                format!("{} on pid {} for {}s.", p.tool, app.pid(), app.trace_secs),
                warn,
            )
        }
        PendingAction::Snapshot => (
            "Capture evidence snapshot?".into(),
            format!(
                "Copy /proc/{}, the executable and deleted-but-open files into the case.",
                app.pid()
            ),
            "Reads the target's memory-backed files. The target is not modified.".into(),
        ),
        PendingAction::RecoverFd(fd, target) => (
            format!("Recover fd {fd}?"),
            format!(
                "Copy {} into the evidence case.",
                crate::util::truncate(target, 60)
            ),
            "Reads the open descriptor. Useful for deleted-but-open payloads and logs.".into(),
        ),
        PendingAction::Quit => (
            "Quit while a trace is running?".into(),
            "A capture is still active and will be stopped.".into(),
            "Collected output so far is kept and hashed.".into(),
        ),
    };
    let area = centered(screen, 68, 9);
    let inner = modal(f, app, area, &title, Glyph::Warn);
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {body}"),
            Style::default().fg(theme.palette.fg),
        )),
        Line::from(""),
        Line::from(Span::styled(format!("  {warn}"), theme.dim())),
        Line::from(""),
        Line::from(vec![
            Span::styled("   ", theme.base()),
            Span::styled(" y / Enter ", theme.selection()),
            Span::styled("  confirm      ", theme.dim()),
            Span::styled(
                " n / Esc ",
                Style::default().fg(theme.palette.bg).bg(theme.palette.dim),
            ),
            Span::styled("  cancel", theme.dim()),
        ]),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .style(theme.panel())
            .alignment(Alignment::Left),
        inner,
    );
}
