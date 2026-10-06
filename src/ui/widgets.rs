//! Small reusable rendering helpers built on the shared [`Theme`].

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use super::theme::Theme;

/// A bordered panel with a left-aligned title. Focused panels get a bold,
/// accented border to drive the block design.
pub fn panel<'a>(theme: &Theme, title: impl Into<Line<'a>>, focused: bool) -> Block<'a> {
    let border_style = if focused {
        theme.border_focus()
    } else {
        theme.border()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(theme.border_type())
        .border_style(border_style)
        .title_top(title.into())
        .title_style(theme.title())
        .style(theme.panel());
    if focused {
        block.border_set(theme.border_set())
    } else {
        block
    }
}

/// A titled block whose title carries an icon and an optional right-aligned tag.
pub fn titled<'a>(theme: &Theme, icon: &'a str, name: &'a str, focused: bool) -> Block<'a> {
    let title = Line::from(vec![
        Span::raw(" "),
        Span::styled(icon, theme.accent()),
        Span::raw(" "),
        Span::styled(name, theme.title()),
        Span::raw(" "),
    ]);
    panel(theme, title, focused)
}

/// Renders a key/value table into `area` with aligned keys.
pub fn render_kv(f: &mut Frame, theme: &Theme, area: Rect, rows: &[(String, Line)]) {
    let key_w = rows
        .iter()
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(0)
        .min(26);
    let lines: Vec<Line> = rows
        .iter()
        .map(|(k, v)| {
            let mut spans = vec![Span::styled(format!(" {k:<key_w$}  "), theme.dim())];
            spans.extend(v.spans.iter().cloned());
            Line::from(spans)
        })
        .collect();
    f.render_widget(Paragraph::new(lines).style(theme.panel()), area);
}

/// A single-line text gauge: `label [███████░░░] 72%` sized to `width`.
pub fn bar_line<'a>(
    theme: &Theme,
    label: &str,
    label_w: usize,
    ratio: f64,
    bar_w: usize,
    suffix: &str,
) -> Line<'a> {
    let ratio = ratio.clamp(0.0, 1.0);
    let filled = (ratio * bar_w as f64).round() as usize;
    let color = theme.gauge_color(ratio);
    let full = "█".repeat(filled.min(bar_w));
    let empty = "░".repeat(bar_w.saturating_sub(filled));
    Line::from(vec![
        Span::styled(format!("{label:<label_w$} "), theme.dim()),
        Span::styled(full, Style::default().fg(color)),
        Span::styled(empty, theme.faint()),
        Span::styled(
            format!(" {suffix}"),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
    ])
}

/// Braille sparkline from a series, scaled to its own max.
pub fn sparkline(data: &[u64], width: usize) -> String {
    const LEVELS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    if data.is_empty() || width == 0 {
        return " ".repeat(width);
    }
    let slice = &data[data.len().saturating_sub(width)..];
    let max = slice.iter().copied().max().unwrap_or(1).max(1);
    let mut out = String::new();
    for _ in 0..width.saturating_sub(slice.len()) {
        out.push(' ');
    }
    for &v in slice {
        let idx = ((v as f64 / max as f64) * (LEVELS.len() - 1) as f64).round() as usize;
        out.push(LEVELS[idx.min(LEVELS.len() - 1)]);
    }
    out
}

/// Centers a rectangle of the given size inside `area`.
pub fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    }
}

/// Centered rectangle sized by percentage, clamped to a maximum.
pub fn centered_pct(area: Rect, pct_w: u16, pct_h: u16, max_w: u16, max_h: u16) -> Rect {
    centered(
        area,
        (area.width * pct_w / 100).min(max_w),
        (area.height * pct_h / 100).min(max_h),
    )
}

/// Clamps a scroll offset so the view never runs past the content.
pub fn clamp_scroll(scroll: &mut usize, total: usize, visible: usize) -> usize {
    let max = total.saturating_sub(visible);
    *scroll = (*scroll).min(max);
    *scroll
}

/// A paragraph that wraps and uses the panel background.
pub fn para<'a>(theme: &Theme, lines: Vec<Line<'a>>) -> Paragraph<'a> {
    Paragraph::new(lines)
        .style(theme.panel())
        .wrap(Wrap { trim: false })
}

/// Splits `area` into `n` equal columns with one cell of spacing.
pub fn columns(area: Rect, n: usize) -> Vec<Rect> {
    let constraints: Vec<Constraint> = (0..n).map(|_| Constraint::Ratio(1, n as u32)).collect();
    ratatui::layout::Layout::horizontal(constraints)
        .spacing(1)
        .split(area)
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparkline_scales() {
        let s = sparkline(&[0, 50, 100], 3);
        assert_eq!(s.chars().count(), 3);
        assert!(s.starts_with('▁'));
        assert!(s.ends_with('█'));
        assert_eq!(sparkline(&[], 4), "    ");
        assert_eq!(sparkline(&[5], 3).chars().count(), 3);
    }

    #[test]
    fn scroll_clamps() {
        let mut s = 100;
        assert_eq!(clamp_scroll(&mut s, 10, 5), 5);
        assert_eq!(s, 5);
    }
}
