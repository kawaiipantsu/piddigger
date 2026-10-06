//! Color palettes, border styles and glyph sets for the TUI.
//!
//! Five palettes span dark → light. Each one is a flat set of named roles so
//! widgets never hard-code a color. Glyphs come in a Nerd Font set and an
//! ASCII fallback for terminals without a patched font.

use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::border;
use ratatui::widgets::BorderType;

use crate::findings::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeKind {
    ThugsRed,
    Midnight,
    Carbon,
    Dracula,
    Twilight,
    Daylight,
}

impl ThemeKind {
    pub const ALL: [ThemeKind; 6] = [
        ThemeKind::ThugsRed,
        ThemeKind::Midnight,
        ThemeKind::Carbon,
        ThemeKind::Dracula,
        ThemeKind::Twilight,
        ThemeKind::Daylight,
    ];

    pub fn name(self) -> &'static str {
        match self {
            ThemeKind::ThugsRed => "thugsred",
            ThemeKind::Midnight => "midnight",
            ThemeKind::Carbon => "carbon",
            ThemeKind::Dracula => "dracula",
            ThemeKind::Twilight => "twilight",
            ThemeKind::Daylight => "daylight",
        }
    }

    /// Dark, semi-light or light — shown in the status bar.
    pub fn tone(self) -> &'static str {
        match self {
            ThemeKind::ThugsRed | ThemeKind::Midnight | ThemeKind::Carbon | ThemeKind::Dracula => {
                "dark"
            }
            ThemeKind::Twilight => "semi-light",
            ThemeKind::Daylight => "light",
        }
    }

    pub fn from_name(s: &str) -> Option<ThemeKind> {
        Self::ALL.into_iter().find(|t| t.name() == s)
    }

    pub fn next(self) -> ThemeKind {
        let all = Self::ALL;
        let i = all.iter().position(|t| *t == self).unwrap_or(0);
        all[(i + 1) % all.len()]
    }
}

/// Resolved color roles for one palette.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub bg: Color,
    pub panel: Color,
    pub fg: Color,
    pub dim: Color,
    pub faint: Color,
    pub border: Color,
    pub border_focus: Color,
    pub accent: Color,
    pub accent2: Color,
    pub title: Color,
    pub good: Color,
    pub warn: Color,
    pub bad: Color,
    pub crit: Color,
    pub info: Color,
    pub selection_bg: Color,
    pub selection_fg: Color,
    pub header_bg: Color,
    pub header_fg: Color,
}

const fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color::Rgb(r, g, b)
}

pub struct Theme {
    pub kind: ThemeKind,
    pub palette: Palette,
    pub nerd: bool,
    pub ascii: bool,
}

impl Theme {
    pub fn new(kind: ThemeKind, nerd: bool, ascii: bool) -> Theme {
        Theme {
            palette: palette(kind),
            kind,
            nerd,
            ascii,
        }
    }

    pub fn base(&self) -> Style {
        Style::default().fg(self.palette.fg).bg(self.palette.bg)
    }
    pub fn panel(&self) -> Style {
        Style::default().fg(self.palette.fg).bg(self.palette.panel)
    }
    pub fn dim(&self) -> Style {
        Style::default().fg(self.palette.dim)
    }
    pub fn faint(&self) -> Style {
        Style::default().fg(self.palette.faint)
    }
    pub fn accent(&self) -> Style {
        Style::default()
            .fg(self.palette.accent)
            .add_modifier(Modifier::BOLD)
    }
    pub fn title(&self) -> Style {
        Style::default()
            .fg(self.palette.title)
            .add_modifier(Modifier::BOLD)
    }
    pub fn border(&self) -> Style {
        Style::default().fg(self.palette.border)
    }
    pub fn border_focus(&self) -> Style {
        Style::default()
            .fg(self.palette.border_focus)
            .add_modifier(Modifier::BOLD)
    }
    pub fn selection(&self) -> Style {
        Style::default()
            .fg(self.palette.selection_fg)
            .bg(self.palette.selection_bg)
            .add_modifier(Modifier::BOLD)
    }
    pub fn header(&self) -> Style {
        Style::default()
            .fg(self.palette.header_fg)
            .bg(self.palette.header_bg)
            .add_modifier(Modifier::BOLD)
    }

    pub fn severity_color(&self, sev: Severity) -> Color {
        match sev {
            Severity::High => self.palette.crit,
            Severity::Medium => self.palette.bad,
            Severity::Low => self.palette.warn,
            Severity::Info => self.palette.info,
        }
    }

    pub fn severity_style(&self, sev: Severity) -> Style {
        Style::default()
            .fg(self.severity_color(sev))
            .add_modifier(Modifier::BOLD)
    }

    /// Picks a color on the good → bad scale for a 0.0–1.0 ratio.
    pub fn gauge_color(&self, ratio: f64) -> Color {
        if ratio >= 0.9 {
            self.palette.crit
        } else if ratio >= 0.75 {
            self.palette.bad
        } else if ratio >= 0.5 {
            self.palette.warn
        } else {
            self.palette.good
        }
    }

    pub fn border_type(&self) -> BorderType {
        if self.ascii {
            BorderType::Plain
        } else {
            BorderType::Rounded
        }
    }

    /// Heavy border set used for the focused panel's block theme.
    pub fn border_set(&self) -> border::Set<'static> {
        if self.ascii {
            border::PLAIN
        } else {
            border::THICK
        }
    }

    pub fn g(&self, glyph: Glyph) -> &'static str {
        glyph.pick(self.nerd)
    }
}

/// Named glyphs with Nerd Font and ASCII variants (a catalog; not all are used yet).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum Glyph {
    Overview,
    Files,
    Network,
    Memory,
    Security,
    Threads,
    Env,
    Tree,
    Activity,
    Findings,
    Trace,
    Evidence,
    Help,
    Process,
    Clock,
    Cpu,
    Ram,
    Disk,
    Shield,
    Skull,
    Warn,
    Check,
    Cross,
    Dot,
    Arrow,
    ArrowUp,
    ArrowDown,
    Lock,
    Unlock,
    Bolt,
    Bug,
    Folder,
    Socket,
    Pipe,
    Chip,
    Record,
    Pause,
    Play,
    Search,
    Logo,
    Deleted,
    Root,
    User,
}

impl Glyph {
    fn pick(self, nerd: bool) -> &'static str {
        use Glyph::*;
        let (n, a) = match self {
            Overview => ("\u{f0e4}", "[O]"),
            Files => ("\u{f0214}", "[F]"),
            Network => ("\u{f0318}", "[N]"),
            Memory => ("\u{f035b}", "[M]"),
            Security => ("\u{f0297}", "[S]"),
            Threads => ("\u{f035c}", "[T]"),
            Env => ("\u{f0b07}", "[E]"),
            Tree => ("\u{f0764}", "[Y]"),
            Activity => ("\u{f040a}", "[A]"),
            Findings => ("\u{f0e0e}", "[!]"),
            Trace => ("\u{f0547}", "[R]"),
            Evidence => ("\u{f0193}", "[C]"),
            Help => ("\u{f059}", "[?]"),
            Process => ("\u{f0214}", "#"),
            Clock => ("\u{f017}", "@"),
            Cpu => ("\u{f0ee0}", "cpu"),
            Ram => ("\u{f035b}", "ram"),
            Disk => ("\u{f02ca}", "io"),
            Shield => ("\u{f0297}", "sec"),
            Skull => ("\u{f068c}", "(!)"),
            Warn => ("\u{f0026}", "!"),
            Check => ("\u{f012c}", "v"),
            Cross => ("\u{f0156}", "x"),
            Dot => ("\u{f0765}", "*"),
            Arrow => ("\u{f0142}", "->"),
            ArrowUp => ("\u{f005d}", "^"),
            ArrowDown => ("\u{f0045}", "v"),
            Lock => ("\u{f033e}", "[L]"),
            Unlock => ("\u{f0fc6}", "[U]"),
            Bolt => ("\u{f0e7}", "!"),
            Bug => ("\u{f0a70}", "bug"),
            Folder => ("\u{f0770}", "d"),
            Socket => ("\u{f0318}", "sock"),
            Pipe => ("\u{f0af2}", "pipe"),
            Chip => ("\u{f061a}", "[]"),
            Record => ("\u{f044a}", "REC"),
            Pause => ("\u{f03e4}", "||"),
            Play => ("\u{f040a}", ">"),
            Search => ("\u{f0349}", "/"),
            Logo => ("\u{f0ff6}", "#"),
            Deleted => ("\u{f0a7a}", "DEL"),
            Root => ("\u{f0297}", "#"),
            User => ("\u{f0004}", "$"),
        };
        if nerd {
            n
        } else {
            a
        }
    }
}

fn palette(kind: ThemeKind) -> Palette {
    match kind {
        // The THUGS(red) brand: red on near-black, matching the project banner.
        ThemeKind::ThugsRed => Palette {
            bg: rgb(10, 10, 12),
            panel: rgb(16, 16, 19),
            fg: rgb(222, 224, 230),
            dim: rgb(150, 150, 160),
            faint: rgb(96, 98, 108),
            border: rgb(74, 28, 34),
            border_focus: rgb(255, 43, 59),
            accent: rgb(255, 43, 59),
            accent2: rgb(255, 120, 90),
            title: rgb(240, 242, 248),
            good: rgb(64, 220, 120),
            warn: rgb(240, 196, 90),
            bad: rgb(255, 140, 80),
            crit: rgb(255, 43, 59),
            info: rgb(120, 180, 235),
            selection_bg: rgb(74, 20, 26),
            selection_fg: rgb(255, 235, 236),
            header_bg: rgb(18, 10, 12),
            header_fg: rgb(255, 70, 85),
        },
        // Deep blue-black, calmer house style.
        ThemeKind::Midnight => Palette {
            bg: rgb(9, 14, 26),
            panel: rgb(14, 21, 38),
            fg: rgb(205, 218, 240),
            dim: rgb(138, 155, 184),
            faint: rgb(88, 104, 134),
            border: rgb(52, 68, 95),
            border_focus: rgb(80, 190, 255),
            accent: rgb(80, 190, 255),
            accent2: rgb(90, 230, 180),
            title: rgb(230, 237, 248),
            good: rgb(90, 230, 180),
            warn: rgb(240, 200, 90),
            bad: rgb(255, 150, 90),
            crit: rgb(255, 66, 103),
            info: rgb(120, 170, 230),
            selection_bg: rgb(30, 54, 86),
            selection_fg: rgb(235, 245, 255),
            header_bg: rgb(20, 29, 50),
            header_fg: rgb(130, 200, 255),
        },
        // Neutral graphite, lower saturation for long shifts.
        ThemeKind::Carbon => Palette {
            bg: rgb(18, 18, 20),
            panel: rgb(26, 27, 30),
            fg: rgb(214, 216, 222),
            dim: rgb(150, 153, 161),
            faint: rgb(98, 101, 110),
            border: rgb(60, 63, 70),
            border_focus: rgb(235, 110, 90),
            accent: rgb(235, 140, 90),
            accent2: rgb(120, 200, 180),
            title: rgb(236, 238, 243),
            good: rgb(120, 200, 150),
            warn: rgb(232, 196, 110),
            bad: rgb(240, 150, 100),
            crit: rgb(240, 90, 90),
            info: rgb(130, 180, 220),
            selection_bg: rgb(48, 44, 42),
            selection_fg: rgb(245, 238, 235),
            header_bg: rgb(34, 36, 40),
            header_fg: rgb(235, 150, 110),
        },
        // Popular high-contrast dark palette.
        ThemeKind::Dracula => Palette {
            bg: rgb(40, 42, 54),
            panel: rgb(47, 49, 63),
            fg: rgb(248, 248, 242),
            dim: rgb(170, 172, 190),
            faint: rgb(98, 114, 164),
            border: rgb(98, 114, 164),
            border_focus: rgb(189, 147, 249),
            accent: rgb(189, 147, 249),
            accent2: rgb(139, 233, 253),
            title: rgb(248, 248, 242),
            good: rgb(80, 250, 123),
            warn: rgb(241, 250, 140),
            bad: rgb(255, 184, 108),
            crit: rgb(255, 85, 85),
            info: rgb(139, 233, 253),
            selection_bg: rgb(68, 71, 90),
            selection_fg: rgb(248, 248, 242),
            header_bg: rgb(56, 58, 74),
            header_fg: rgb(255, 121, 198),
        },
        // Muted parchment: light surfaces, dark ink, still easy on contrast.
        ThemeKind::Twilight => Palette {
            bg: rgb(222, 224, 232),
            panel: rgb(233, 235, 242),
            fg: rgb(36, 42, 58),
            dim: rgb(84, 92, 112),
            faint: rgb(130, 138, 158),
            border: rgb(168, 176, 196),
            border_focus: rgb(32, 110, 200),
            accent: rgb(32, 110, 200),
            accent2: rgb(0, 150, 130),
            title: rgb(22, 28, 44),
            good: rgb(24, 140, 90),
            warn: rgb(176, 120, 0),
            bad: rgb(200, 90, 30),
            crit: rgb(200, 30, 60),
            info: rgb(40, 110, 190),
            selection_bg: rgb(198, 214, 240),
            selection_fg: rgb(20, 30, 54),
            header_bg: rgb(243, 244, 249),
            header_fg: rgb(32, 110, 200),
        },
        // Bright white, maximum readability in a lit room.
        ThemeKind::Daylight => Palette {
            bg: rgb(250, 250, 252),
            panel: rgb(255, 255, 255),
            fg: rgb(24, 28, 40),
            dim: rgb(78, 86, 104),
            faint: rgb(138, 146, 164),
            border: rgb(198, 204, 216),
            border_focus: rgb(0, 92, 200),
            accent: rgb(0, 92, 200),
            accent2: rgb(0, 140, 120),
            title: rgb(12, 16, 28),
            good: rgb(10, 130, 70),
            warn: rgb(168, 112, 0),
            bad: rgb(196, 78, 16),
            crit: rgb(196, 16, 48),
            info: rgb(20, 96, 180),
            selection_bg: rgb(214, 228, 250),
            selection_fg: rgb(10, 20, 44),
            header_bg: rgb(241, 243, 248),
            header_fg: rgb(0, 92, 200),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn themes_cycle_and_resolve() {
        assert_eq!(ThemeKind::from_name("dracula"), Some(ThemeKind::Dracula));
        assert_eq!(ThemeKind::from_name("thugsred"), Some(ThemeKind::ThugsRed));
        assert_eq!(ThemeKind::Daylight.next(), ThemeKind::ThugsRed);
        assert_eq!(ThemeKind::ALL.len(), 6);
        for t in ThemeKind::ALL {
            let _ = palette(t);
            assert!(!t.tone().is_empty());
        }
    }

    #[test]
    fn glyphs_have_both_variants() {
        let t = Theme::new(ThemeKind::Midnight, false, true);
        assert_eq!(t.g(Glyph::Check), "v");
        let t = Theme::new(ThemeKind::Midnight, true, false);
        assert_ne!(t.g(Glyph::Check), "v");
    }
}
