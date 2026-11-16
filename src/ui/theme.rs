//! The palette. All colours live here, as roles (background, text, border, ...); widgets ask
//! for a style by role and never name a colour. Three themes: Catppuccin Mocha (dark) and
//! Latte (light) with their official values, and `terminal`, which uses the ANSI colours and
//! the terminal's own background and text so it follows the terminal's theme.

use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Block;

pub const THEMES: [&str; 3] = ["mocha", "latte", "terminal"];

/// The theme name as stored in `config.toml`; the old `dark` / `light` are mocha / latte and
/// anything unknown is mocha.
pub fn canonical(name: &str) -> &'static str {
    match name {
        "latte" | "light" => "latte",
        "terminal" => "terminal",
        _ => "mocha",
    }
}

/// How many colours the terminal shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    TrueColor,
    /// The 256-colour palette: RGB values are replaced by the nearest entry.
    Indexed256,
    /// 16 ANSI colours only: only the `terminal` theme works.
    Ansi16,
    /// `NO_COLOR`: no colours at all; selection is bold and inverted.
    NoColor,
}

impl ColorMode {
    /// From the environment values (kept apart from `std::env` so tests can feed them).
    pub fn from_env(
        no_color: Option<&str>,
        colorterm: Option<&str>,
        term: Option<&str>,
        windows_terminal: bool,
    ) -> Self {
        if no_color.is_some_and(|v| !v.is_empty()) {
            return Self::NoColor;
        }
        let ct = colorterm.unwrap_or("").to_ascii_lowercase();
        if ct == "truecolor" || ct == "24bit" || windows_terminal {
            return Self::TrueColor;
        }
        if term.is_some_and(|t| t.contains("256color")) {
            return Self::Indexed256;
        }
        Self::Ansi16
    }

    pub fn detect() -> Self {
        let var = |k: &str| std::env::var(k).ok();
        Self::from_env(
            var("NO_COLOR").as_deref(),
            var("COLORTERM").as_deref(),
            var("TERM").as_deref(),
            var("WT_SESSION").is_some(),
        )
    }
}

const fn rgb(v: u32) -> (u8, u8, u8) {
    ((v >> 16) as u8, (v >> 8) as u8, v as u8)
}
type Rgb = (u8, u8, u8);

/// A palette in RGB: the roles of Catppuccin (base, mantle, surface0, overlay0, mauve, text,
/// subtext0, green, yellow, red, blue).
struct Palette {
    bg: Rgb,
    panel: Rgb,
    text: Rgb,
    muted: Rgb,
    border: Rgb,
    accent: Rgb,
    selection: Rgb,
    ok: Rgb,
    warn: Rgb,
    err: Rgb,
    info: Rgb,
}

const MOCHA: Palette = Palette {
    bg: rgb(0x1e1e2e),
    panel: rgb(0x181825),
    text: rgb(0xcdd6f4),
    muted: rgb(0xa6adc8),
    border: rgb(0x6c7086),
    accent: rgb(0xcba6f7),
    selection: rgb(0x313244),
    ok: rgb(0xa6e3a1),
    warn: rgb(0xf9e2af),
    err: rgb(0xf38ba8),
    info: rgb(0x89b4fa),
};

const LATTE: Palette = Palette {
    bg: rgb(0xeff1f5),
    panel: rgb(0xe6e9ef),
    text: rgb(0x4c4f69),
    // Deviation from the role table: subtext1, not subtext0 (#6c6f85 is 4.37:1 on base, below the
    // 4.5:1 that hints and explanations need). Mocha keeps subtext0.
    muted: rgb(0x5c5f77),
    border: rgb(0x9ca0b0),
    accent: rgb(0x8839ef),
    selection: rgb(0xccd0da),
    ok: rgb(0x40a02b),
    warn: rgb(0xdf8e1d),
    err: rgb(0xd20f39),
    info: rgb(0x1e66f5),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub bg: Color,
    pub panel_bg: Color,
    pub text: Color,
    pub muted: Color,
    pub border: Color,
    pub border_active: Color,
    pub selection: Color,
    pub accent: Color,
    pub ok: Color,
    pub warn: Color,
    pub err: Color,
    pub info: Color,
    /// Fill the screen and the panels with the theme's background.
    pub fill: bool,
    /// Selection is drawn by inversion (the terminal theme and `NO_COLOR`).
    invert_selection: bool,
    /// Warnings are bold: Latte's yellow is too pale for plain text.
    bold_warn: bool,
    no_color: bool,
}

fn quantize(c: Rgb, mode: ColorMode) -> Color {
    match mode {
        ColorMode::TrueColor => Color::Rgb(c.0, c.1, c.2),
        _ => Color::Indexed(nearest_256(c)),
    }
}

/// The nearest entry of the xterm 256-colour palette (the 6x6x6 cube or the grey ramp).
pub fn nearest_256((r, g, b): Rgb) -> u8 {
    const LEVELS: [i32; 6] = [0, 95, 135, 175, 215, 255];
    let near = |v: u8| {
        (0..6)
            .min_by_key(|&i| (LEVELS[i] - i32::from(v)).abs())
            .unwrap_or(0)
    };
    let (ri, gi, bi) = (near(r), near(g), near(b));
    let cube = (LEVELS[ri], LEVELS[gi], LEVELS[bi]);
    let avg = (i32::from(r) + i32::from(g) + i32::from(b)) / 3;
    let gi_idx = ((avg - 8 + 5) / 10).clamp(0, 23);
    let gv = 8 + 10 * gi_idx;
    let dist = |p: (i32, i32, i32)| {
        (p.0 - i32::from(r)).pow(2) + (p.1 - i32::from(g)).pow(2) + (p.2 - i32::from(b)).pow(2)
    };
    if dist((gv, gv, gv)) < dist(cube) {
        (232 + gi_idx) as u8
    } else {
        (16 + 36 * ri + 6 * gi + bi) as u8
    }
}

impl Theme {
    fn from_palette(p: &Palette, mode: ColorMode, transparent: bool, light: bool) -> Self {
        let q = |c| quantize(c, mode);
        Self {
            bg: q(p.bg),
            panel_bg: q(p.panel),
            text: q(p.text),
            muted: q(p.muted),
            border: q(p.border),
            border_active: q(p.accent),
            selection: q(p.selection),
            accent: q(p.accent),
            ok: q(p.ok),
            warn: q(p.warn),
            err: q(p.err),
            info: q(p.info),
            fill: !transparent,
            invert_selection: false,
            bold_warn: light,
            no_color: false,
        }
    }

    pub fn mocha(mode: ColorMode, transparent: bool) -> Self {
        Self::from_palette(&MOCHA, mode, transparent, false)
    }

    pub fn latte(mode: ColorMode, transparent: bool) -> Self {
        Self::from_palette(&LATTE, mode, transparent, true)
    }

    /// ANSI colours; the background and the text are the terminal's own.
    pub fn terminal() -> Self {
        Self {
            bg: Color::Reset,
            panel_bg: Color::Reset,
            text: Color::Reset,
            muted: Color::DarkGray,
            border: Color::DarkGray,
            border_active: Color::Magenta,
            selection: Color::Reset,
            accent: Color::Magenta,
            ok: Color::Green,
            warn: Color::Yellow,
            err: Color::Red,
            info: Color::Blue,
            fill: false,
            invert_selection: true,
            bold_warn: false,
            no_color: false,
        }
    }

    /// `NO_COLOR`: nothing is coloured; roles differ by bold, dim and inversion.
    pub fn no_color() -> Self {
        Self {
            bg: Color::Reset,
            panel_bg: Color::Reset,
            text: Color::Reset,
            muted: Color::Reset,
            border: Color::Reset,
            border_active: Color::Reset,
            selection: Color::Reset,
            accent: Color::Reset,
            ok: Color::Reset,
            warn: Color::Reset,
            err: Color::Reset,
            info: Color::Reset,
            fill: false,
            invert_selection: true,
            bold_warn: true,
            no_color: true,
        }
    }

    /// The theme for a stored name. Without 256 colours only `terminal` works; `forced` says
    /// that the choice was overridden (the caller logs it).
    pub fn resolve(name: &str, mode: ColorMode, transparent: bool) -> (Self, bool) {
        match (mode, canonical(name)) {
            (ColorMode::NoColor, _) => (Self::no_color(), false),
            (ColorMode::Ansi16, n) => (Self::terminal(), n != "terminal"),
            (_, "latte") => (Self::latte(mode, transparent), false),
            (_, "terminal") => (Self::terminal(), false),
            (_, _) => (Self::mocha(mode, transparent), false),
        }
    }

    /// Only the Catppuccin themes have a background of their own to make transparent.
    pub fn has_own_background(name: &str, mode: ColorMode) -> bool {
        matches!(mode, ColorMode::TrueColor | ColorMode::Indexed256)
            && canonical(name) != "terminal"
    }

    /// The base of the whole screen: the background and the text colour.
    pub fn base(&self) -> Style {
        let mut s = Style::default().fg(self.text);
        if self.fill {
            s = s.bg(self.bg);
        }
        s
    }

    /// A panel: bordered, filled with the panel colour.
    pub fn block(&self, focused: bool) -> Block<'static> {
        let mut style = Style::default();
        if self.fill {
            style = style.bg(self.panel_bg);
        }
        Block::bordered()
            .border_style(self.border(focused))
            .style(style)
    }

    /// The "PRIVACY" badge: loud on purpose, so a screenshot cannot miss that it is on.
    pub fn privacy_badge(&self) -> Style {
        if self.no_color {
            return Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED);
        }
        Style::default()
            .fg(self.bg_for_badge())
            .bg(self.warn)
            .add_modifier(Modifier::BOLD)
    }

    /// Dark text on the warning colour; black in themes that have no dark background colour.
    fn bg_for_badge(&self) -> Color {
        if self.fill {
            self.bg
        } else {
            Color::Black
        }
    }

    pub fn text(&self) -> Style {
        Style::default().fg(self.text)
    }
    pub fn muted(&self) -> Style {
        let s = Style::default().fg(self.muted);
        if self.no_color {
            s.add_modifier(Modifier::DIM)
        } else {
            s
        }
    }
    pub fn title(&self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }
    pub fn border(&self, focused: bool) -> Style {
        if focused {
            Style::default()
                .fg(self.border_active)
                .add_modifier(if self.no_color {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                })
        } else {
            Style::default().fg(self.border)
        }
    }
    pub fn selected(&self) -> Style {
        if self.invert_selection {
            Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        } else {
            Style::default()
                .bg(self.selection)
                .add_modifier(Modifier::BOLD)
        }
    }
    pub fn good(&self) -> Style {
        Style::default().fg(self.ok)
    }
    pub fn warn(&self) -> Style {
        let s = Style::default().fg(self.warn);
        if self.bold_warn {
            s.add_modifier(Modifier::BOLD)
        } else {
            s
        }
    }
    pub fn bad(&self) -> Style {
        let s = Style::default().fg(self.err);
        if self.no_color {
            s.add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            s
        }
    }
    pub fn info(&self) -> Style {
        Style::default().fg(self.info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lum(c: Rgb) -> f64 {
        let f = |v: u8| {
            let v = f64::from(v) / 255.0;
            if v <= 0.03928 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * f(c.0) + 0.7152 * f(c.1) + 0.0722 * f(c.2)
    }

    fn contrast(a: Rgb, b: Rgb) -> f64 {
        let (x, y) = (lum(a), lum(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }

    #[test]
    fn text_and_muted_text_contrast_is_at_least_4_5_in_mocha_and_latte() {
        for (name, p) in [("mocha", &MOCHA), ("latte", &LATTE)] {
            for (bg_name, bg) in [("bg", p.bg), ("panel", p.panel)] {
                for (fg_name, fg) in [("text", p.text), ("muted", p.muted)] {
                    let c = contrast(fg, bg);
                    assert!(c >= 4.5, "{name}: {fg_name} on {bg_name} is {c:.2}:1");
                }
            }
            // On the selected row only plain text is held to 4.5:1: Latte's muted text on its
            // official surface0 is 4.05:1 (checked below as the floor, listed in the report).
            let c = contrast(p.text, p.selection);
            assert!(c >= 4.5, "{name}: text on selection is {c:.2}:1");
            let c = contrast(p.muted, p.selection);
            assert!(c >= 4.0, "{name}: muted on selection is {c:.2}:1");
        }
    }

    #[test]
    fn color_mode_from_environment() {
        use ColorMode::*;
        let m = ColorMode::from_env;
        assert_eq!(m(Some("1"), Some("truecolor"), None, false), NoColor);
        assert_eq!(m(Some(""), Some("truecolor"), None, false), TrueColor);
        assert_eq!(m(None, Some("24bit"), Some("xterm"), false), TrueColor);
        assert_eq!(m(None, None, Some("xterm-256color"), false), Indexed256);
        assert_eq!(m(None, None, Some("linux"), false), Ansi16);
        assert_eq!(m(None, None, None, false), Ansi16);
        assert_eq!(m(None, None, None, true), TrueColor);
    }

    #[test]
    fn ansi16_forces_the_terminal_theme() {
        let (t, forced) = Theme::resolve("mocha", ColorMode::Ansi16, false);
        assert!(forced && t == Theme::terminal());
        let (t, forced) = Theme::resolve("terminal", ColorMode::Ansi16, false);
        assert!(!forced && t == Theme::terminal());
        let (t, _) = Theme::resolve("light", ColorMode::TrueColor, false);
        assert_eq!(t, Theme::latte(ColorMode::TrueColor, false));
    }

    #[test]
    fn rgb_maps_to_the_nearest_256_entry() {
        assert_eq!(nearest_256((0, 0, 0)), 16);
        assert_eq!(nearest_256((255, 255, 255)), 231);
        assert_eq!(nearest_256((255, 0, 0)), 196);
        let g = nearest_256((0x30, 0x30, 0x30));
        assert!((232..=255).contains(&g), "grey ramp: {g}");
        assert!(matches!(
            Theme::mocha(ColorMode::Indexed256, false).bg,
            Color::Indexed(_)
        ));
    }

    #[test]
    fn no_color_theme_has_no_colors() {
        let t = Theme::no_color();
        for s in [
            t.text(),
            t.muted(),
            t.good(),
            t.bad(),
            t.warn(),
            t.selected(),
        ] {
            assert!(s.fg.is_none_or(|c| c == Color::Reset), "{s:?}");
            assert!(s.bg.is_none_or(|c| c == Color::Reset), "{s:?}");
        }
        assert!(t.selected().add_modifier.contains(Modifier::REVERSED));
    }
}
