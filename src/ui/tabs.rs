//! Per-view rendering. Each tab draws into the content area to the right of
//! the navigation sidebar.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;

use super::theme::{Glyph, Theme};
use super::widgets::{self, bar_line, clamp_scroll, para, sparkline, titled};
use crate::activity::EventKind;
use crate::app::App;
use crate::app::Tab;
use crate::findings::Severity;
use crate::model::{FdKind, MapKind};
use crate::util;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    match app.tab {
        Tab::Overview => overview(f, app, area),
        Tab::Tree => tree(f, app, area),
        Tab::Files => files(f, app, area),
        Tab::Network => network(f, app, area),
        Tab::Memory => memory(f, app, area),
        Tab::Security => security(f, app, area),
        Tab::Threads => threads(f, app, area),
        Tab::Environment => environment(f, app, area),
        Tab::Activity => activity(f, app, area),
        Tab::Findings => findings(f, app, area),
        Tab::Trace => trace(f, app, area),
        Tab::Evidence => evidence(f, app, area),
    }
}

fn kv<'a>(k: &str, v: impl Into<String>, theme: &Theme) -> (String, Line<'a>) {
    (
        k.to_string(),
        Line::from(Span::styled(
            v.into(),
            Style::default().fg(theme.palette.fg),
        )),
    )
}
fn kv_styled<'a>(k: &str, v: impl Into<String>, style: Style) -> (String, Line<'a>) {
    (k.to_string(), Line::from(Span::styled(v.into(), style)))
}

fn state_style(theme: &Theme, state: &str) -> Style {
    if state.starts_with('R') {
        Style::default()
            .fg(theme.palette.good)
            .add_modifier(Modifier::BOLD)
    } else if state.starts_with('Z') || state.starts_with('X') {
        Style::default()
            .fg(theme.palette.crit)
            .add_modifier(Modifier::BOLD)
    } else if state.starts_with('D') || state.starts_with('T') || state.starts_with('t') {
        Style::default().fg(theme.palette.warn)
    } else {
        Style::default().fg(theme.palette.fg)
    }
}

// --- Overview dashboard --------------------------------------------------------

fn overview(f: &mut Frame, app: &App, area: Rect) {
    // Three rows: identity + open files, network + maps, meters + findings.
    let [top, mid, bot] = Layout::vertical([
        Constraint::Length(13),
        Constraint::Min(7),
        Constraint::Length(9),
    ])
    .areas(area);

    let [ident_a, files_a] =
        Layout::horizontal([Constraint::Percentage(54), Constraint::Percentage(46)]).areas(top);
    overview_identity(f, app, ident_a);
    overview_files(f, app, files_a);

    let [net_a, map_a] =
        Layout::horizontal([Constraint::Percentage(54), Constraint::Percentage(46)]).areas(mid);
    overview_network(f, app, net_a);
    overview_maps(f, app, map_a);

    let [meters_a, find_a] =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(bot);
    overview_meters(f, app, meters_a);
    overview_findings(f, app, find_a);
}

fn overview_identity(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let s = &app.snap;
    let id = &s.ident;
    let block = titled(
        theme,
        theme.g(Glyph::Process),
        "Process Information",
        app.tab == Tab::Overview,
    );
    let inner = block.inner(area);
    f.render_widget(block, area);
    let deleted_style = Style::default()
        .fg(theme.palette.crit)
        .add_modifier(Modifier::BOLD);
    let exe_line = if s.exe.deleted || s.exe.memfd {
        kv_styled("Exe", &s.exe.path, deleted_style)
    } else {
        kv("Exe", &s.exe.path, theme)
    };
    let rows = vec![
        kv("PID", format!("{}", id.pid), theme),
        kv(
            "PPID",
            format!(
                "{}  ({})",
                id.ppid,
                s.ancestry.first().map(|p| p.comm.as_str()).unwrap_or("?")
            ),
            theme,
        ),
        kv("Name", &id.comm, theme),
        kv_styled("State", &id.state, state_style(theme, &id.state)),
        kv("User", format!("{} (uid {})", id.user, id.uid[0]), theme),
        kv(
            "Started",
            format!(
                "{}  (up {})",
                util::unix_short(id.start_time),
                util::human_duration(id.age_secs)
            ),
            theme,
        ),
        kv("CWD", &id.cwd, theme),
        exe_line,
        kv(
            "Cmdline",
            if id.cmdline.is_empty() {
                "(none)".into()
            } else {
                util::truncate(&id.cmdline.join(" "), 80)
            },
            theme,
        ),
        kv(
            "SHA-256",
            s.exe.sha256.clone().unwrap_or_else(|| "unavailable".into()),
            theme,
        ),
    ];
    widgets::render_kv(f, theme, inner, &rows);
}

fn overview_files(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let title = format!("Open Files ({})", app.snap.fds.len());
    let block = titled(theme, theme.g(Glyph::Files), &title, false);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let header = Row::new(["FD", "TYPE", "PATH"]).style(theme.header());
    let rows = app
        .snap
        .fds
        .iter()
        .take(inner.height.saturating_sub(1) as usize)
        .map(|fd| {
            let style = if fd.deleted {
                Style::default().fg(theme.palette.crit)
            } else if matches!(fd.kind, FdKind::Socket | FdKind::Memfd | FdKind::AnonInode) {
                Style::default().fg(theme.palette.accent2)
            } else {
                Style::default().fg(theme.palette.fg)
            };
            let ty = if fd.deleted { "del" } else { fd.kind.label() };
            Row::new([
                Cell::from(fd.fd.to_string()),
                Cell::from(ty),
                Cell::from(util::truncate(
                    &fd.target,
                    inner.width.saturating_sub(12) as usize,
                )),
            ])
            .style(style)
        });
    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Length(7),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .style(theme.panel());
    f.render_widget(table, inner);
}

fn overview_network(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let socks: Vec<_> = app
        .snap
        .sockets
        .iter()
        .filter(|s| !s.proto.starts_with("netlink"))
        .collect();
    let title = format!("Network Connections ({})", socks.len());
    let block = titled(theme, theme.g(Glyph::Network), &title, false);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let header = Row::new(["PROTO", "LOCAL", "REMOTE", "STATE"]).style(theme.header());
    let rows = socks
        .iter()
        .take(inner.height.saturating_sub(1) as usize)
        .map(|s| {
            Row::new([
                Cell::from(s.proto.clone()),
                Cell::from(util::truncate(&s.local, 24)),
                Cell::from(if s.remote.is_empty() {
                    "*".into()
                } else {
                    util::truncate(&s.remote, 24)
                }),
                Cell::from(Span::styled(
                    s.state.clone(),
                    net_state_style(theme, &s.state),
                )),
            ])
        });
    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Percentage(36),
            Constraint::Percentage(36),
            Constraint::Length(12),
        ],
    )
    .header(header)
    .style(theme.panel());
    f.render_widget(table, inner);
}

fn net_state_style(theme: &Theme, state: &str) -> Style {
    let c = match state {
        "ESTABLISHED" => theme.palette.good,
        "LISTEN" => theme.palette.info,
        "TIME_WAIT" | "CLOSE_WAIT" | "FIN_WAIT1" | "FIN_WAIT2" | "CLOSING" | "LAST_ACK" => {
            theme.palette.warn
        }
        "SYN_SENT" | "SYN_RECV" => theme.palette.accent2,
        _ => theme.palette.dim,
    };
    Style::default().fg(c).add_modifier(Modifier::BOLD)
}

fn overview_maps(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let title = format!("Memory Maps ({})", app.snap.maps.len());
    let block = titled(theme, theme.g(Glyph::Memory), &title, false);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let header = Row::new(["ADDRESS", "PERMS", "PATH"]).style(theme.header());
    // Prefer the interesting mappings in the overview.
    let mut maps: Vec<_> = app.snap.maps.iter().collect();
    maps.sort_by_key(|m| {
        let rank = if m.writable() && m.executable() {
            0
        } else if matches!(m.kind, MapKind::Deleted | MapKind::Memfd) {
            1
        } else if m.executable() && m.kind == MapKind::File {
            2
        } else {
            3
        };
        (rank, u64::MAX - m.size())
    });
    let rows = maps
        .iter()
        .take(inner.height.saturating_sub(1) as usize)
        .map(|m| {
            let style = map_style(theme, m);
            let path = if m.path.is_empty() {
                format!("[{}]", m.kind.label())
            } else {
                m.path.clone()
            };
            Row::new([
                Cell::from(format!("{:012x}", m.start)),
                Cell::from(m.perms.clone()),
                Cell::from(util::truncate(
                    &path,
                    inner.width.saturating_sub(22) as usize,
                )),
            ])
            .style(style)
        });
    let table = Table::new(
        rows,
        [
            Constraint::Length(13),
            Constraint::Length(6),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .style(theme.panel());
    f.render_widget(table, inner);
}

fn map_style(theme: &Theme, m: &crate::model::MapEntry) -> Style {
    if m.writable() && m.executable() {
        Style::default()
            .fg(theme.palette.crit)
            .add_modifier(Modifier::BOLD)
    } else if matches!(m.kind, MapKind::Deleted | MapKind::Memfd) {
        Style::default().fg(theme.palette.bad)
    } else if m.executable() {
        Style::default().fg(theme.palette.accent2)
    } else {
        Style::default().fg(theme.palette.dim)
    }
}

fn overview_meters(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let s = &app.snap;
    let block = titled(theme, theme.g(Glyph::Cpu), "Live Meters", false);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let bar_w = inner.width.saturating_sub(16) as usize;
    let cpu = app.cpu_percent();
    let cpu_ratio = cpu / (100.0 * s.host.num_cpus.max(1) as f64);
    let mem_ratio = if s.mem.mem_total_kb > 0 {
        s.mem.vm_rss_kb as f64 / s.mem.mem_total_kb as f64
    } else {
        0.0
    };
    let lines = vec![
        bar_line(theme, "CPU", 5, cpu_ratio, bar_w, &format!("{cpu:.1}%")),
        Line::from(Span::styled(
            format!(
                "   {}",
                sparkline(
                    &app.cpu_history.iter().copied().collect::<Vec<_>>(),
                    bar_w + 8
                )
            ),
            theme.faint(),
        )),
        bar_line(
            theme,
            "RSS",
            5,
            mem_ratio,
            bar_w,
            &util::human_kb(s.mem.vm_rss_kb),
        ),
        Line::from(Span::styled(
            format!(
                "   {}",
                sparkline(
                    &app.rss_history.iter().copied().collect::<Vec<_>>(),
                    bar_w + 8
                )
            ),
            theme.faint(),
        )),
        Line::from(vec![
            Span::styled("Threads ", theme.dim()),
            Span::styled(format!("{}", s.ident.num_threads), theme.accent()),
            Span::styled("  FDs ", theme.dim()),
            Span::styled(format!("{}", s.fds.len()), theme.accent()),
            Span::styled("  ctx ", theme.dim()),
            Span::styled(
                format!("{}", s.ident.vol_ctxt + s.ident.nonvol_ctxt),
                theme.accent(),
            ),
        ]),
    ];
    f.render_widget(para(theme, lines), inner);
}

fn overview_findings(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let high = app
        .findings
        .iter()
        .filter(|x| x.severity >= Severity::Medium)
        .count();
    let title = format!("Findings ({} · {} notable)", app.findings.len(), high);
    let block = titled(theme, theme.g(Glyph::Findings), &title, false);
    let inner = block.inner(area);
    f.render_widget(block, area);
    if app.findings.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "  no triage findings — nothing stood out",
                theme.dim(),
            )))
            .style(theme.panel()),
            inner,
        );
        return;
    }
    let lines: Vec<Line> = app
        .findings
        .iter()
        .take(inner.height as usize)
        .map(|x| {
            Line::from(vec![
                Span::styled(
                    format!(" {:<8}", x.severity.label()),
                    theme.severity_style(x.severity),
                ),
                Span::styled(
                    util::truncate(&x.title, inner.width.saturating_sub(10) as usize),
                    Style::default().fg(theme.palette.fg),
                ),
            ])
        })
        .collect();
    f.render_widget(para(theme, lines), inner);
}

// --- Generic scrolling list helper ---------------------------------------------

/// Renders a titled, scrollable list of pre-built lines with a scrollbar hint.
fn scroll_list(
    f: &mut Frame,
    app: &App,
    area: Rect,
    icon: Glyph,
    title: &str,
    lines: Vec<Line>,
    selectable: bool,
) {
    let theme = &app.theme;
    let block = titled(theme, theme.g(icon), title, true);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let visible = inner.height as usize;
    let total = lines.len();
    let mut scroll = app.scroll[app.tab.index()];
    if selectable {
        // Keep the selection in view.
        if app.selected >= scroll + visible {
            scroll = app.selected.saturating_sub(visible - 1);
        }
        if app.selected < scroll {
            scroll = app.selected;
        }
    }
    let scroll = clamp_scroll(&mut scroll, total, visible);
    let shown: Vec<Line> = lines.into_iter().skip(scroll).take(visible).collect();
    f.render_widget(Paragraph::new(shown).style(theme.panel()), inner);
    if total > visible {
        let pct = scroll as f64 / (total - visible) as f64;
        let y = inner.y + (pct * (inner.height.saturating_sub(1)) as f64) as u16;
        let bar = Rect {
            x: area.x + area.width - 1,
            y,
            width: 1,
            height: 1,
        };
        f.render_widget(Paragraph::new("█").style(theme.accent()), bar);
    }
}

// --- Tree ----------------------------------------------------------------------

fn tree(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let s = &app.snap;
    let mut lines = Vec::new();
    let arrow = theme.g(Glyph::Arrow);
    // Ancestry from the top down.
    for (depth, p) in s.ancestry.iter().rev().enumerate() {
        let indent = "  ".repeat(depth);
        lines.push(Line::from(vec![
            Span::styled(format!("{indent}{arrow} "), theme.faint()),
            Span::styled(format!("{} ", p.pid), theme.accent()),
            Span::styled(
                format!("{} ", p.comm),
                Style::default().fg(theme.palette.fg),
            ),
            Span::styled(format!("({}) ", p.user), theme.dim()),
            Span::styled(util::truncate(&p.cmdline, 70), theme.faint()),
        ]));
    }
    let depth = s.ancestry.len();
    let indent = "  ".repeat(depth);
    lines.push(Line::from(vec![
        Span::styled(format!("{indent}{} ", theme.g(Glyph::Dot)), theme.accent()),
        Span::styled(format!("{} ", s.ident.pid), theme.accent()),
        Span::styled(
            format!("{} ", s.ident.comm),
            Style::default()
                .fg(theme.palette.title)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("({}) ", s.ident.user), theme.dim()),
        Span::styled("← target", theme.accent()),
    ]));
    for c in &s.children {
        let ind = "  ".repeat(depth + 1);
        let style = if c.exe_deleted {
            Style::default().fg(theme.palette.crit)
        } else {
            Style::default().fg(theme.palette.fg)
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{ind}{arrow} "), theme.faint()),
            Span::styled(
                format!("{} ", c.pid),
                Style::default().fg(theme.palette.accent2),
            ),
            Span::styled(format!("{} ", c.comm), style),
            Span::styled(util::truncate(&c.cmdline, 66), theme.faint()),
        ]));
    }
    if s.children.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("{}  (no children)", "  ".repeat(depth + 1)),
            theme.faint(),
        )));
    }
    let title = format!(
        "Process Tree · {} ancestor(s), {} child(ren)",
        s.ancestry.len(),
        s.children.len()
    );
    scroll_list(f, app, area, Glyph::Tree, &title, lines, false);
}

// --- Files ---------------------------------------------------------------------

fn files(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let deleted_idx: Vec<usize> = app
        .snap
        .fds
        .iter()
        .enumerate()
        .filter(|(_, fd)| fd.deleted && matches!(fd.kind, FdKind::File | FdKind::Memfd))
        .map(|(i, _)| i)
        .collect();
    let mut lines = Vec::new();
    let mut deleted_counter = 0usize;
    for fd in &app.snap.fds {
        let is_recoverable = fd.deleted && matches!(fd.kind, FdKind::File | FdKind::Memfd);
        let selected = is_recoverable && deleted_counter == app.selected;
        if is_recoverable {
            deleted_counter += 1;
        }
        let marker = if selected { "▶ " } else { "  " };
        let kind_style = match fd.kind {
            _ if fd.deleted => Style::default()
                .fg(theme.palette.crit)
                .add_modifier(Modifier::BOLD),
            FdKind::Socket => Style::default().fg(theme.palette.accent2),
            FdKind::Memfd | FdKind::AnonInode => Style::default().fg(theme.palette.warn),
            FdKind::Pipe => Style::default().fg(theme.palette.info),
            _ => Style::default().fg(theme.palette.fg),
        };
        let size = fd
            .size
            .map(|s| format!(" {}", util::human_bytes(s)))
            .unwrap_or_default();
        let flags = fd.flags.clone().unwrap_or_default();
        let mut spans = vec![
            Span::styled(marker, theme.accent()),
            Span::styled(format!("{:>4} ", fd.fd), theme.dim()),
            Span::styled(
                format!("{:<6} ", if fd.deleted { "DEL" } else { fd.kind.label() }),
                kind_style,
            ),
            Span::styled(
                util::truncate(&fd.target, area.width.saturating_sub(34) as usize),
                Style::default().fg(theme.palette.fg),
            ),
        ];
        if !size.is_empty() {
            spans.push(Span::styled(size, theme.faint()));
        }
        if !flags.is_empty() {
            spans.push(Span::styled(format!("  {flags}"), theme.faint()));
        }
        lines.push(Line::from(spans));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  no open descriptors (or permission denied)",
            theme.faint(),
        )));
    }
    let title = format!(
        "Open Files · {} fd(s) · {} deleted (Enter = recover selected)",
        app.snap.fds.len(),
        deleted_idx.len()
    );
    scroll_list(f, app, area, Glyph::Files, &title, lines, true);
}

// --- Network -------------------------------------------------------------------

fn network(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let mut lines = Vec::new();
    for s in &app.snap.sockets {
        let star = if s.is_listening() {
            Span::styled("◆ ", Style::default().fg(theme.palette.info))
        } else if s.state == "ESTABLISHED" {
            Span::styled("● ", Style::default().fg(theme.palette.good))
        } else {
            Span::styled("· ", theme.faint())
        };
        let danger = s.proto == "packet" || s.proto.starts_with("raw");
        let proto_style = if danger {
            Style::default()
                .fg(theme.palette.crit)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.palette.accent2)
        };
        let mut spans = vec![
            star,
            Span::styled(format!("{:<14} ", s.proto), proto_style),
            Span::styled(
                format!("{:<26}", util::truncate(&s.local, 26)),
                Style::default().fg(theme.palette.fg),
            ),
        ];
        if !s.remote.is_empty() {
            spans.push(Span::styled(
                format!(" {} ", theme.g(Glyph::Arrow)),
                theme.faint(),
            ));
            spans.push(Span::styled(
                format!("{:<26}", util::truncate(&s.remote, 26)),
                Style::default().fg(theme.palette.fg),
            ));
        } else {
            spans.push(Span::raw(" ".repeat(30)));
        }
        spans.push(Span::styled(
            format!(" {}", s.state),
            net_state_style(theme, &s.state),
        ));
        if s.rx_queue > 0 || s.tx_queue > 0 {
            spans.push(Span::styled(
                format!("  rxq {} txq {}", s.rx_queue, s.tx_queue),
                theme.faint(),
            ));
        }
        lines.push(Line::from(spans));
        if !s.detail.is_empty() && (s.proto.starts_with("unix") || s.proto == "socket") {
            lines.push(Line::from(Span::styled(
                format!("      {}", util::truncate(&s.detail, 80)),
                theme.faint(),
            )));
        }
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  no sockets held by this process",
            theme.faint(),
        )));
    }
    let title = format!("Network / Sockets · {} socket(s)", app.snap.sockets.len());
    scroll_list(f, app, area, Glyph::Network, &title, lines, false);
}

// --- Memory --------------------------------------------------------------------

fn memory(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let [sum_a, maps_a] = Layout::vertical([Constraint::Length(9), Constraint::Min(4)]).areas(area);
    let s = &app.snap;
    let m = &s.mem;
    let block = titled(theme, theme.g(Glyph::Ram), "Memory Summary", false);
    let inner = block.inner(sum_a);
    f.render_widget(block, sum_a);
    let cols = widgets::columns(inner, 3);
    let g = Style::default().fg(theme.palette.fg);
    widgets::render_kv(
        f,
        theme,
        cols[0],
        &[
            kv_styled("RSS", util::human_kb(m.vm_rss_kb), g),
            kv_styled("VmSize", util::human_kb(m.vm_size_kb), g),
            kv_styled("Peak", util::human_kb(m.vm_peak_kb), g),
            kv_styled("HWM", util::human_kb(m.vm_hwm_kb), g),
        ],
    );
    widgets::render_kv(
        f,
        theme,
        cols[1],
        &[
            kv_styled("Anon", util::human_kb(m.rss_anon_kb), g),
            kv_styled("File", util::human_kb(m.rss_file_kb), g),
            kv_styled("Shmem", util::human_kb(m.rss_shmem_kb), g),
            kv_styled("Swap", util::human_kb(m.vm_swap_kb), g),
        ],
    );
    widgets::render_kv(
        f,
        theme,
        cols[2],
        &[
            kv_styled(
                "PSS",
                m.pss_kb.map(util::human_kb).unwrap_or_else(|| "n/a".into()),
                g,
            ),
            kv_styled(
                "PrivDirty",
                m.private_dirty_kb
                    .map(util::human_kb)
                    .unwrap_or_else(|| "n/a".into()),
                g,
            ),
            kv_styled("Stack", util::human_kb(m.vm_stk_kb), g),
            kv_styled(
                "Exe/Lib",
                format!(
                    "{}/{}",
                    util::human_kb(m.vm_exe_kb),
                    util::human_kb(m.vm_lib_kb)
                ),
                g,
            ),
        ],
    );

    let mut lines = Vec::new();
    for mp in &s.maps {
        let style = map_style(theme, mp);
        let path = if mp.path.is_empty() {
            format!("[{}]", mp.kind.label())
        } else {
            mp.path.clone()
        };
        let flag = if mp.writable() && mp.executable() {
            " ⚠ RWX"
        } else if matches!(mp.kind, MapKind::Deleted | MapKind::Memfd) {
            " ⚠"
        } else {
            ""
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {:012x}-{:012x} ", mp.start, mp.end),
                theme.faint(),
            ),
            Span::styled(format!("{} ", mp.perms), style),
            Span::styled(format!("{:>9} ", util::human_bytes(mp.size())), theme.dim()),
            Span::styled(
                util::truncate(&path, area.width.saturating_sub(42) as usize),
                style,
            ),
            Span::styled(flag, Style::default().fg(theme.palette.crit)),
        ]));
    }
    let title = format!("Memory Maps · {} region(s)", s.maps.len());
    // Render maps as its own scroll list by reusing the scroll offset.
    let block = titled(theme, theme.g(Glyph::Memory), &title, true);
    let inner = block.inner(maps_a);
    f.render_widget(block, maps_a);
    let visible = inner.height as usize;
    let mut scroll = app.scroll[app.tab.index()];
    let scroll = clamp_scroll(&mut scroll, lines.len(), visible);
    let shown: Vec<Line> = lines.into_iter().skip(scroll).take(visible).collect();
    f.render_widget(Paragraph::new(shown).style(theme.panel()), inner);
}

// --- Security ------------------------------------------------------------------

fn security(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let s = &app.snap;
    let sec = &s.security;
    let mut lines = Vec::new();
    let push_head = |lines: &mut Vec<Line>, t: &str| {
        lines.push(Line::from(Span::styled(format!(" {t}"), theme.accent())));
    };

    push_head(&mut lines, "Privileges");
    lines.push(kvl(theme, "UID r/e/s/fs", format!("{:?}", s.ident.uid)));
    lines.push(kvl(theme, "GID r/e/s/fs", format!("{:?}", s.ident.gid)));
    lines.push(kvl(
        theme,
        "Groups",
        s.ident
            .groups
            .iter()
            .map(|g| g.to_string())
            .collect::<Vec<_>>()
            .join(","),
    ));
    if let Some(l) = s.ident.login_uid {
        lines.push(kvl(theme, "loginuid", format!("{l} (audit trail)")));
    }
    lines.push(kvl(
        theme,
        "no_new_privs",
        if sec.no_new_privs { "yes" } else { "no" },
    ));
    let seccomp_style = if sec.seccomp == "disabled" {
        theme.faint()
    } else {
        Style::default().fg(theme.palette.good)
    };
    lines.push(Line::from(vec![
        Span::styled(format!("   {:<16}", "seccomp"), theme.dim()),
        Span::styled(sec.seccomp.clone(), seccomp_style),
        Span::styled(
            sec.seccomp_filters
                .map(|n| format!("  ({n} filters)"))
                .unwrap_or_default(),
            theme.faint(),
        ),
    ]));
    if let Some(label) = &sec.lsm_label {
        lines.push(kvl(theme, "LSM", label.clone()));
    }
    if sec.tracer_pid > 0 {
        lines.push(Line::from(vec![
            Span::styled(format!("   {:<16}", "TracerPid"), theme.dim()),
            Span::styled(
                format!(
                    "{} ({})",
                    sec.tracer_pid,
                    sec.tracer_comm.clone().unwrap_or_default()
                ),
                Style::default()
                    .fg(theme.palette.warn)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
    }

    lines.push(Line::from(""));
    push_head(&mut lines, "Capabilities (effective)");
    if sec.cap_eff.names.is_empty() {
        lines.push(Line::from(Span::styled("   none", theme.faint())));
    } else {
        for name in &sec.cap_eff.names {
            let dangerous =
                crate::procfs::DANGEROUS_CAPS.contains(&name.trim_start_matches("cap_"));
            let style = if dangerous {
                Style::default()
                    .fg(theme.palette.crit)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.palette.fg)
            };
            lines.push(Line::from(vec![
                Span::styled("   • ", theme.faint()),
                Span::styled(name.clone(), style),
                Span::styled(if dangerous { "  (powerful)" } else { "" }, theme.faint()),
            ]));
        }
    }
    lines.push(Line::from(vec![
        Span::styled("   bounding set: ", theme.dim()),
        Span::styled(format!("{} cap(s)", sec.cap_bnd.names.len()), theme.faint()),
    ]));

    lines.push(Line::from(""));
    push_head(&mut lines, "Namespaces");
    for ns in &s.namespaces {
        let differs = ns.differs_from_init();
        let style = if differs {
            Style::default().fg(theme.palette.accent2)
        } else {
            theme.dim()
        };
        lines.push(Line::from(vec![
            Span::styled(format!("   {:<8}", ns.name), theme.dim()),
            Span::styled(ns.link.clone(), style),
            Span::styled(if differs { "  (own)" } else { "  (host)" }, theme.faint()),
        ]));
    }
    if !s.cgroups.is_empty() {
        lines.push(kvl(theme, "cgroup", s.cgroups.join(" ")));
    }
    scroll_list(
        f,
        app,
        area,
        Glyph::Security,
        "Security & Isolation",
        lines,
        false,
    );
}

fn kvl<'a>(theme: &Theme, k: &str, v: impl Into<String>) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("   {k:<16}"), theme.dim()),
        Span::styled(v.into(), Style::default().fg(theme.palette.fg)),
    ])
}

// --- Threads -------------------------------------------------------------------

fn threads(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let mut lines = vec![Line::from(vec![Span::styled(
        format!(
            "  {:>8} {:<16} {:<6} {:>8} {:>8} {:>4}  {}",
            "TID", "COMM", "STATE", "UTIME", "STIME", "CPU", "WCHAN"
        ),
        theme.header(),
    )])];
    for t in &app.snap.threads {
        lines.push(Line::from(vec![
            Span::styled(format!("  {:>8} ", t.tid), theme.accent()),
            Span::styled(
                format!("{:<16} ", util::truncate(&t.comm, 16)),
                Style::default().fg(theme.palette.fg),
            ),
            Span::styled(format!("{:<6} ", t.state), state_style(theme, &t.state)),
            Span::styled(
                format!("{:>8} {:>8} ", t.utime_ticks, t.stime_ticks),
                theme.dim(),
            ),
            Span::styled(format!("{:>4}  ", t.processor), theme.faint()),
            Span::styled(util::truncate(&t.wchan, 40), theme.faint()),
        ]));
    }
    let title = format!("Threads · {} task(s)", app.snap.threads.len());
    scroll_list(f, app, area, Glyph::Threads, &title, lines, false);
}

// --- Environment ---------------------------------------------------------------

fn environment(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let sensitive = [
        "LD_PRELOAD",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "HISTFILE",
        "HISTSIZE",
        "PATH",
    ];
    let mut lines = Vec::new();
    for v in &app.snap.environ {
        let hot = sensitive.contains(&v.key.as_str());
        let key_style = if hot {
            Style::default()
                .fg(theme.palette.crit)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.palette.accent2)
        };
        let value = if app.show_env_values {
            util::truncate(
                &v.value,
                area.width.saturating_sub(v.key.chars().count() as u16 + 8) as usize,
            )
        } else {
            format!("[{} chars hidden]", v.value.len())
        };
        lines.push(Line::from(vec![
            Span::styled("  ", theme.base()),
            Span::styled(v.key.clone(), key_style),
            Span::styled("=", theme.faint()),
            Span::styled(value, Style::default().fg(theme.palette.fg)),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  environ unavailable (permission denied or empty)",
            theme.faint(),
        )));
    }
    let title = format!(
        "Environment · {} var(s) · 'n' {} values",
        app.snap.environ.len(),
        if app.show_env_values { "hide" } else { "show" }
    );
    scroll_list(f, app, area, Glyph::Env, &title, lines, false);
}

// --- Activity ------------------------------------------------------------------

fn activity(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let mut lines = Vec::new();
    for e in &app.timeline {
        let (sign_style, kind_color) = event_style(theme, e.kind, e.sign);
        let time = e.at.get(11..19).unwrap_or("--:--:--");
        lines.push(Line::from(vec![
            Span::styled(format!("  {time} "), theme.faint()),
            Span::styled(format!("{} ", e.sign), sign_style),
            Span::styled(
                format!("{:<7}", e.kind.label()),
                Style::default().fg(kind_color),
            ),
            Span::styled(
                util::truncate(&e.text, area.width.saturating_sub(24) as usize),
                Style::default().fg(theme.palette.fg),
            ),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            if app.demo_mode {
                "  (demo) watching for changes…"
            } else {
                "  watching for changes… fd, socket, thread, child and exec events appear here"
            },
            theme.faint(),
        )));
    }
    let title = format!("Activity Timeline · {} event(s)", app.timeline.len());
    scroll_list(f, app, area, Glyph::Activity, &title, lines, false);
}

fn event_style(theme: &Theme, kind: EventKind, sign: char) -> (Style, ratatui::style::Color) {
    let sign_color = match sign {
        '+' => theme.palette.good,
        '-' => theme.palette.bad,
        _ => theme.palette.warn,
    };
    let kind_color = match kind {
        EventKind::Net => theme.palette.accent2,
        EventKind::File => theme.palette.info,
        EventKind::Map => theme.palette.crit,
        EventKind::Child => theme.palette.accent,
        EventKind::Thread => theme.palette.warn,
        EventKind::State => theme.palette.dim,
    };
    (
        Style::default().fg(sign_color).add_modifier(Modifier::BOLD),
        kind_color,
    )
}

// --- Findings ------------------------------------------------------------------

fn findings(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let mut lines = Vec::new();
    for x in &app.findings {
        lines.push(Line::from(vec![
            Span::styled(
                format!(" ▌{:<7}", x.severity.label()),
                theme.severity_style(x.severity),
            ),
            Span::styled(
                x.title.clone(),
                Style::default()
                    .fg(theme.palette.title)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("  [{}]", x.category), theme.faint()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("    why  ", theme.dim()),
            Span::styled(x.detail, Style::default().fg(theme.palette.fg)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("    evid ", theme.dim()),
            Span::styled(
                util::truncate(&x.evidence, area.width.saturating_sub(12) as usize),
                theme.faint(),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("    next ", theme.dim()),
            Span::styled(x.advice, Style::default().fg(theme.palette.accent2)),
        ]));
        lines.push(Line::from(""));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  no findings — the triage heuristics did not flag anything",
            theme.dim(),
        )));
        lines.push(Line::from(Span::styled(
            "  absence of findings is not proof the process is benign",
            theme.faint(),
        )));
    }
    let title = format!(
        "Findings · {} lead(s) — leads, not verdicts",
        app.findings.len()
    );
    scroll_list(f, app, area, Glyph::Findings, &title, lines, false);
}

// --- Trace ---------------------------------------------------------------------

fn trace(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    if app.runs.is_empty() {
        let block = titled(theme, theme.g(Glyph::Trace), "Live Trace", true);
        let inner = block.inner(area);
        f.render_widget(block, area);
        let lines = vec![
            Line::from(""),
            Line::from(Span::styled("  No capture running.", theme.dim())),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Press ", theme.dim()),
                Span::styled("R", theme.accent()),
                Span::styled(
                    " to open the trace menu: strace, ltrace, perf, bpftrace,",
                    theme.dim(),
                ),
            ]),
            Line::from(Span::styled(
                "  tcpdump, gdb backtraces and gcore memory images.",
                theme.dim(),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Every capture is written into the evidence case and hashed.",
                theme.faint(),
            )),
            Line::from(Span::styled(
                "  Each profile states its impact: observe · ptrace · pause.",
                theme.faint(),
            )),
        ];
        f.render_widget(para(theme, lines), inner);
        return;
    }
    let run = app
        .active_run
        .and_then(|i| app.runs.get(i))
        .unwrap_or(&app.runs[app.runs.len() - 1]);
    let state = run.state();
    let (status, status_style) = match &state {
        crate::tools::RunState::Running => {
            let left = run.secs.saturating_sub(run.started.elapsed().as_secs());
            (
                format!(
                    "● RUNNING  {}s elapsed / ~{}s",
                    run.started.elapsed().as_secs(),
                    if run.profile.timed { run.secs } else { left }
                ),
                theme.severity_style(Severity::Low),
            )
        }
        crate::tools::RunState::Finished(code) => (
            format!(
                "✓ FINISHED (exit {})",
                code.map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".into())
            ),
            Style::default().fg(theme.palette.good),
        ),
        crate::tools::RunState::Failed(e) => (
            format!("✗ FAILED: {e}"),
            Style::default().fg(theme.palette.crit),
        ),
    };
    let title = format!(
        "Trace · {} · {} · {}",
        run.profile.title,
        run.profile.impact.label(),
        status
    );
    let block = titled(theme, theme.g(Glyph::Trace), &title, true);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let [bar, body] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(inner);
    let started = run.started_at.get(11..19).unwrap_or("--:--:--");
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" since ", theme.dim()),
            Span::styled(format!("{started} "), theme.faint()),
            Span::styled(format!("· {} lines ", run.captured_lines()), theme.dim()),
            Span::styled("· ", theme.faint()),
            Span::styled(
                util::truncate(
                    &run.argv.first().map(|a| a.join(" ")).unwrap_or_default(),
                    inner.width.saturating_sub(40) as usize,
                ),
                theme.faint(),
            ),
            Span::styled("  ", theme.base()),
            Span::styled(status.clone(), status_style),
        ]))
        .style(theme.panel()),
        bar,
    );
    let visible = body.height as usize;
    let tail = run.tail(visible + app.scroll[app.tab.index()]);
    let shown: Vec<Line> = tail
        .iter()
        .take(visible)
        .map(|l| {
            Line::from(Span::styled(
                format!(
                    " {}",
                    util::truncate(l, body.width.saturating_sub(2) as usize)
                ),
                trace_line_style(theme, l),
            ))
        })
        .collect();
    f.render_widget(Paragraph::new(shown).style(theme.panel()), body);
}

fn trace_line_style(theme: &Theme, line: &str) -> Style {
    if line.starts_with("###") {
        Style::default()
            .fg(theme.palette.accent)
            .add_modifier(Modifier::BOLD)
    } else if line.contains("= -1")
        || line.contains("errno")
        || line.contains("EACCES")
        || line.contains("denied")
    {
        Style::default().fg(theme.palette.bad)
    } else if line.contains("execve") || line.contains("connect(") || line.contains("fork") {
        Style::default().fg(theme.palette.accent2)
    } else {
        Style::default().fg(theme.palette.fg)
    }
}

// --- Evidence ------------------------------------------------------------------

fn evidence(f: &mut Frame, app: &App, area: Rect) {
    let theme = &app.theme;
    let [top, bottom] = Layout::vertical([Constraint::Length(11), Constraint::Min(3)]).areas(area);
    let [hashes_a, custody_head] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(top);

    // Hashes & timestamps panel (mirrors the banner).
    let block = titled(
        theme,
        theme.g(Glyph::Evidence),
        "Hashes & Timestamps",
        false,
    );
    let inner = block.inner(hashes_a);
    f.render_widget(block, hashes_a);
    let s = &app.snap;
    let g = Style::default().fg(theme.palette.fg);
    let rows = vec![
        kv_styled(
            "Exe SHA-256",
            s.exe.sha256.clone().unwrap_or_else(|| "n/a".into()),
            g,
        ),
        kv_styled(
            "Exe size",
            s.exe
                .size
                .map(util::human_bytes)
                .unwrap_or_else(|| "n/a".into()),
            g,
        ),
        kv_styled(
            "Exe owner",
            s.exe.owner.clone().unwrap_or_else(|| "n/a".into()),
            g,
        ),
        kv_styled(
            "mtime",
            s.exe.mtime.clone().unwrap_or_else(|| "n/a".into()),
            g,
        ),
        kv_styled(
            "ctime",
            s.exe.ctime.clone().unwrap_or_else(|| "n/a".into()),
            g,
        ),
        kv_styled("Start", util::unix_short(s.ident.start_time), g),
        kv_styled("Collected", s.taken_at.clone(), g),
        kv_styled("ELF", s.exe.elf.clone().unwrap_or_else(|| "n/a".into()), g),
    ];
    widgets::render_kv(f, theme, inner, &rows);

    // Case status panel.
    let block = titled(theme, theme.g(Glyph::Shield), "Evidence Case", false);
    let inner = block.inner(custody_head);
    f.render_widget(block, custody_head);
    let mut lines = Vec::new();
    match &app.case {
        Some(case) => {
            lines.push(kvl(theme, "Case", case.id.clone()));
            lines.push(kvl(theme, "Path", case.dir.to_string_lossy().into_owned()));
            lines.push(kvl(theme, "Artifacts", format!("{}", case.entries.len())));
            let bytes: u64 = case.entries.iter().map(|e| e.size).sum();
            lines.push(kvl(theme, "Size", util::human_bytes(bytes)));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  write-once · mode 0400 · SHA256SUMS",
                theme.faint(),
            )));
            lines.push(Line::from(vec![
                Span::styled("  verify: ", theme.dim()),
                Span::styled("v", theme.accent()),
                Span::styled("   new snapshot: ", theme.dim()),
                Span::styled("s", theme.accent()),
            ]));
        }
        None => {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  No case opened yet.",
                theme.dim(),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("  Press ", theme.dim()),
                Span::styled("s", theme.accent()),
                Span::styled(" to snapshot /proc, the executable and", theme.dim()),
            ]));
            lines.push(Line::from(Span::styled(
                "  deleted-but-open files into a hashed case folder.",
                theme.dim(),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  Timestamps and SHA-256 are preserved for every artifact.",
                theme.faint(),
            )));
        }
    }
    f.render_widget(para(theme, lines), inner);

    // Chain-of-custody log.
    let block = titled(theme, theme.g(Glyph::Record), "Chain of Custody", true);
    let inner = block.inner(bottom);
    f.render_widget(block, bottom);
    let log_lines: Vec<Line> = match &app.case {
        Some(case) => {
            let visible = inner.height as usize;
            case.log_tail
                .iter()
                .rev()
                .take(visible)
                .rev()
                .map(|l| {
                    Line::from(Span::styled(
                        format!(
                            " {}",
                            util::truncate(l, inner.width.saturating_sub(2) as usize)
                        ),
                        custody_style(theme, l),
                    ))
                })
                .collect()
        }
        None => vec![Line::from(Span::styled(
            "  (no case — the custody log starts when you snapshot)",
            theme.faint(),
        ))],
    };
    f.render_widget(Paragraph::new(log_lines).style(theme.panel()), inner);
}

fn custody_style(theme: &Theme, line: &str) -> Style {
    if line.contains(" OPEN ") || line.contains(" CLOSE ") {
        Style::default()
            .fg(theme.palette.accent)
            .add_modifier(Modifier::BOLD)
    } else if line.contains(" COLLECT ") || line.contains(" SNAPSHOT ") {
        Style::default().fg(theme.palette.good)
    } else if line.contains("WARN") || line.contains("FAILED") || line.contains("!!") {
        Style::default().fg(theme.palette.crit)
    } else if line.contains(" VERIFY ") {
        Style::default().fg(theme.palette.info)
    } else {
        theme.dim()
    }
}
