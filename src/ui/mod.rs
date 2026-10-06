//! Terminal rendering and input handling.
//!
//! Layout mirrors the project banner: a header strip, a left navigation
//! sidebar, the active view, and a footer with key hints and the motto.

mod overlays;
mod tabs;
pub mod theme;
mod widgets;

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::{App, Overlay, PendingAction, Tab, ToastKind};
use theme::Glyph;
use widgets::panel;

pub const MOTTO: &str = "Investigate. Understand. Contain.";
pub const TAGLINE: &str = "Live PID Forensics for Blue Teams";

/// Each sidebar entry: its tab, icon and single-key accelerator.
struct NavItem {
    tab: Tab,
    glyph: Glyph,
    key: char,
}

const NAV: [NavItem; 12] = [
    NavItem {
        tab: Tab::Overview,
        glyph: Glyph::Overview,
        key: '1',
    },
    NavItem {
        tab: Tab::Tree,
        glyph: Glyph::Tree,
        key: '2',
    },
    NavItem {
        tab: Tab::Files,
        glyph: Glyph::Files,
        key: '3',
    },
    NavItem {
        tab: Tab::Network,
        glyph: Glyph::Network,
        key: '4',
    },
    NavItem {
        tab: Tab::Memory,
        glyph: Glyph::Memory,
        key: '5',
    },
    NavItem {
        tab: Tab::Security,
        glyph: Glyph::Security,
        key: '6',
    },
    NavItem {
        tab: Tab::Threads,
        glyph: Glyph::Threads,
        key: '7',
    },
    NavItem {
        tab: Tab::Environment,
        glyph: Glyph::Env,
        key: '8',
    },
    NavItem {
        tab: Tab::Activity,
        glyph: Glyph::Activity,
        key: '9',
    },
    NavItem {
        tab: Tab::Findings,
        glyph: Glyph::Findings,
        key: '0',
    },
    NavItem {
        tab: Tab::Trace,
        glyph: Glyph::Trace,
        key: 'r',
    },
    NavItem {
        tab: Tab::Evidence,
        glyph: Glyph::Evidence,
        key: 'c',
    },
];

pub fn draw(f: &mut Frame, app: &App) {
    let theme = &app.theme;
    let area = f.area();
    f.render_widget(Block::default().style(theme.base()), area);

    if area.width < 80 || area.height < 20 {
        let msg = Paragraph::new(vec![
            Line::from(Span::styled("piddigger", theme.accent())),
            Line::from(Span::styled(
                format!(
                    "terminal too small: {}×{} (need ≥ 80×20)",
                    area.width, area.height
                ),
                theme.dim(),
            )),
        ])
        .alignment(Alignment::Center);
        f.render_widget(msg, widgets::centered(area, 60, 3));
        return;
    }

    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(area);
    draw_header(f, app, header);
    draw_footer(f, app, footer);

    let sidebar_w = if area.width >= 120 { 24 } else { 18 };
    let [nav, content] =
        Layout::horizontal([Constraint::Length(sidebar_w), Constraint::Min(0)]).areas(body);
    draw_nav(f, app, nav);

    let content = content.inner(ratatui::layout::Margin {
        horizontal: 0,
        vertical: 0,
    });
    tabs::draw(f, app, content);

    draw_toast(f, app, content);

    match &app.overlay {
        Overlay::None => {}
        Overlay::Help => overlays::help(f, app, area),
        Overlay::ProcessPicker => overlays::process_picker(f, app, area),
        Overlay::ThemePicker => overlays::theme_picker(f, app, area),
        Overlay::TraceMenu => overlays::trace_menu(f, app, area),
        Overlay::Confirm(action) => overlays::confirm(f, app, area, action),
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let p = &theme.palette;
    let left = Line::from(vec![
        Span::styled(" ", theme.base()),
        Span::styled(theme.g(Glyph::Logo), theme.accent()),
        Span::styled(" piddigger ", theme.accent()),
        Span::styled(format!("v{}", env!("CARGO_PKG_VERSION")), theme.faint()),
    ]);
    let center = Line::from(Span::styled(TAGLINE, theme.dim())).alignment(Alignment::Center);
    let right = Line::from(vec![
        Span::styled("Rust", theme.dim()),
        Span::styled(" • ", theme.faint()),
        Span::styled("TUI", theme.dim()),
        Span::styled(" • ", theme.faint()),
        Span::styled("Forensics ", theme.dim()),
    ])
    .alignment(Alignment::Right);
    let bg = Block::default().style(ratatui::style::Style::default().bg(p.header_bg));
    f.render_widget(bg, area);
    f.render_widget(Paragraph::new(left), area);
    f.render_widget(Paragraph::new(center), area);
    f.render_widget(Paragraph::new(right), area);
}

fn draw_nav(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let block = panel(
        theme,
        Line::from(Span::styled(" MENU ", theme.title())),
        false,
    );
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = Vec::new();
    for item in &NAV {
        let active = app.tab == item.tab;
        let count = tab_badge(app, item.tab);
        let icon = theme.g(item.glyph);
        let label = item.tab.title();
        if active {
            lines.push(Line::from(vec![
                Span::styled(format!(" {icon} "), theme.selection()),
                Span::styled(format!("{label:<10}"), theme.selection()),
                Span::styled(badge_text(&count), theme.selection()),
            ]));
        } else {
            let label_style = if count.as_ref().is_some_and(|(sev, _)| *sev) {
                ratatui::style::Style::default().fg(theme.palette.crit)
            } else {
                theme.panel().fg(theme.palette.fg)
            };
            lines.push(Line::from(vec![
                Span::styled(format!(" {icon} "), theme.accent()),
                Span::styled(format!("{label:<10}"), label_style),
                Span::styled(badge_text(&count), theme.faint()),
            ]));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(" by THUGS(red)", theme.faint())));
    lines.push(Line::from(Span::styled(" Kawaiipantsu", theme.faint())));
    f.render_widget(Paragraph::new(lines).style(theme.panel()), inner);
}

/// Returns (is_severe, text) for a nav badge, e.g. the count of findings or runs.
fn tab_badge(app: &App, tab: Tab) -> Option<(bool, String)> {
    match tab {
        Tab::Findings => {
            let high = app
                .findings
                .iter()
                .filter(|f| f.severity >= crate::findings::Severity::Medium)
                .count();
            (!app.findings.is_empty()).then(|| (high > 0, app.findings.len().to_string()))
        }
        Tab::Files => (!app.snap.fds.is_empty()).then(|| {
            let deleted = app.snap.fds.iter().filter(|f| f.deleted).count();
            (deleted > 0, app.snap.fds.len().to_string())
        }),
        Tab::Network => {
            (!app.snap.sockets.is_empty()).then(|| (false, app.snap.sockets.len().to_string()))
        }
        Tab::Trace => {
            let active = app.runs.iter().filter(|r| r.is_running()).count();
            (active > 0).then(|| (true, format!("●{active}")))
        }
        Tab::Threads => {
            (!app.snap.threads.is_empty()).then(|| (false, app.snap.threads.len().to_string()))
        }
        _ => None,
    }
}

fn badge_text(count: &Option<(bool, String)>) -> String {
    match count {
        Some((_, s)) => format!("{s:>4}"),
        None => "    ".into(),
    }
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let key = |k: &'static str| Span::styled(k, theme.accent());
    let txt = |t: &'static str| Span::styled(t, theme.dim());
    let mut left = vec![
        Span::raw(" "),
        key("[?]"),
        txt(" Help  "),
        key("[Tab]"),
        txt(" Switch  "),
        key("[s]"),
        txt(" Snapshot  "),
        key("[R]"),
        txt(" Trace  "),
        key("[p]"),
        txt(" Attach  "),
        key("[q]"),
        txt(" Quit"),
    ];
    if app.paused {
        left.push(Span::styled(
            "  ◼ PAUSED",
            theme.severity_style(crate::findings::Severity::Low),
        ));
    }
    if app.demo_mode {
        left.push(Span::styled("  ⟨DEMO⟩", theme.accent()));
    }
    f.render_widget(Paragraph::new(Line::from(left)).style(theme.base()), area);
    let right = Line::from(vec![
        Span::styled(MOTTO, theme.accent()),
        Span::styled(" ", theme.base()),
    ])
    .alignment(Alignment::Right);
    f.render_widget(Paragraph::new(right), area);
}

fn draw_toast(f: &mut Frame, app: &App, area: Rect) {
    let Some(toast) = &app.toast else { return };
    let theme = &app.theme;
    let color = match toast.kind {
        ToastKind::Info => theme.palette.info,
        ToastKind::Good => theme.palette.good,
        ToastKind::Warn => theme.palette.warn,
        ToastKind::Error => theme.palette.crit,
    };
    let text = format!(" {} ", toast.text);
    let w = (text.chars().count() as u16 + 2).min(area.width.saturating_sub(2));
    let h = 3u16;
    let rect = Rect {
        x: area.x + area.width.saturating_sub(w) - 1,
        y: area.y + area.height.saturating_sub(h) - 1,
        width: w,
        height: h,
    };
    f.render_widget(ratatui::widgets::Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(theme.border_type())
        .border_style(ratatui::style::Style::default().fg(color))
        .style(theme.panel());
    let p = Paragraph::new(Line::from(Span::styled(
        text,
        ratatui::style::Style::default().fg(color),
    )))
    .block(block)
    .alignment(Alignment::Center);
    f.render_widget(p, rect);
}

// --- Input ---------------------------------------------------------------------

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Applies one key event to the app. Overlays capture input first.
pub fn handle_key(app: &mut App, key: KeyEvent) {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }
    match &app.overlay {
        Overlay::Help => {
            app.overlay = Overlay::None;
            return;
        }
        Overlay::ProcessPicker => return handle_picker_key(app, key),
        Overlay::ThemePicker => return handle_theme_key(app, key),
        Overlay::TraceMenu => return handle_trace_menu_key(app, key),
        Overlay::Confirm(action) => {
            let action = action.clone();
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => app.confirm(action),
                _ => app.overlay = Overlay::None,
            }
            return;
        }
        Overlay::None => {}
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            if app.any_run_active() {
                app.overlay = Overlay::Confirm(PendingAction::Quit);
            } else {
                app.should_quit = true;
            }
        }
        KeyCode::Char('?') | KeyCode::F(1) => app.overlay = Overlay::Help,
        KeyCode::Tab | KeyCode::Right => app.next_tab(),
        KeyCode::BackTab | KeyCode::Left => app.prev_tab(),
        KeyCode::Char('t') => app.cycle_theme(),
        KeyCode::Char('T') => app.overlay = Overlay::ThemePicker,
        KeyCode::Char('p') => app.open_picker(),
        KeyCode::Char(' ') => {
            app.paused = !app.paused;
            let state = if app.paused { "paused" } else { "live" };
            app.toast(ToastKind::Info, format!("refresh {state}"));
        }
        KeyCode::Char('+') | KeyCode::Char('=') => app.adjust_refresh(true),
        KeyCode::Char('-') | KeyCode::Char('_') => app.adjust_refresh(false),
        KeyCode::Char('g') => app.refresh(),
        KeyCode::Char('s') => app.overlay = Overlay::Confirm(PendingAction::Snapshot),
        KeyCode::Char('R') => app.overlay = Overlay::TraceMenu,
        KeyCode::Char('x') => app.stop_active_run(),
        KeyCode::Char('v') => app.verify_case(),
        KeyCode::Char('n') => app.show_env_values = !app.show_env_values,
        KeyCode::Char('j') | KeyCode::Down => app.scroll_down(1),
        KeyCode::Char('k') | KeyCode::Up => app.scroll_up(1),
        KeyCode::PageUp => app.scroll_up(10),
        KeyCode::PageDown => app.scroll_down(10),
        KeyCode::Home => {
            *app.scroll_mut() = 0;
            app.selected = 0;
        }
        KeyCode::Enter => tab_action(app),
        KeyCode::Char(c) => {
            if let Some(item) = NAV.iter().find(|i| i.key == c) {
                app.set_tab(item.tab);
            }
        }
        _ => {}
    }
}

/// Context action for the current tab (e.g. recover the selected deleted file).
fn tab_action(app: &mut App) {
    if app.tab == Tab::Files {
        let deleted: Vec<(i32, String)> = app
            .snap
            .fds
            .iter()
            .filter(|f| {
                f.deleted
                    && matches!(
                        f.kind,
                        crate::model::FdKind::File | crate::model::FdKind::Memfd
                    )
            })
            .map(|f| (f.fd, f.target.clone()))
            .collect();
        if let Some((fd, target)) = deleted.into_iter().nth(app.selected) {
            app.overlay = Overlay::Confirm(PendingAction::RecoverFd(fd, target));
        } else {
            app.toast(ToastKind::Info, "select a deleted file to recover (↑/↓)");
        }
    }
}

fn handle_picker_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => app.overlay = Overlay::None,
        KeyCode::Enter => {
            if let Some(row) = app.filtered_picker().get(app.picker_cursor) {
                let pid = row.pid;
                app.attach_to(pid);
            }
        }
        KeyCode::Up => app.picker_cursor = app.picker_cursor.saturating_sub(1),
        KeyCode::Down => {
            let max = app.filtered_picker().len().saturating_sub(1);
            app.picker_cursor = (app.picker_cursor + 1).min(max);
        }
        KeyCode::Backspace => {
            app.picker_filter.pop();
            app.picker_cursor = 0;
        }
        KeyCode::Char(c) => {
            app.picker_filter.push(c);
            app.picker_cursor = 0;
        }
        _ => {}
    }
}

fn handle_theme_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Enter => app.overlay = Overlay::None,
        KeyCode::Up | KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('k') => {
            let all = theme::ThemeKind::ALL;
            let i = all.iter().position(|t| *t == app.theme.kind).unwrap_or(0);
            let ni = match key.code {
                KeyCode::Up | KeyCode::Char('k') => (i + all.len() - 1) % all.len(),
                _ => (i + 1) % all.len(),
            };
            app.set_theme(all[ni]);
        }
        KeyCode::Char(c) if c.is_ascii_digit() => {
            let idx = c as usize - '1' as usize;
            if let Some(kind) = theme::ThemeKind::ALL.get(idx) {
                app.set_theme(*kind);
            }
        }
        _ => {}
    }
}

fn handle_trace_menu_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => app.overlay = Overlay::None,
        KeyCode::Up | KeyCode::Char('k') => app.trace_cursor = app.trace_cursor.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => {
            app.trace_cursor = (app.trace_cursor + 1).min(crate::tools::PROFILES.len() - 1);
        }
        KeyCode::Char('+') | KeyCode::Char('=') => app.trace_secs = (app.trace_secs + 5).min(600),
        KeyCode::Char('-') | KeyCode::Char('_') => {
            app.trace_secs = app.trace_secs.saturating_sub(5).max(5)
        }
        KeyCode::Enter => {
            let idx = app.trace_cursor;
            app.overlay = Overlay::Confirm(PendingAction::RunProfile(idx));
        }
        _ => {}
    }
}

impl App {
    pub fn scroll_up(&mut self, n: usize) {
        let s = self.scroll_mut();
        *s = s.saturating_sub(n);
        self.selected = self.selected.saturating_sub(n);
    }
    pub fn scroll_down(&mut self, n: usize) {
        *self.scroll_mut() += n;
        self.selected += n;
    }
}
