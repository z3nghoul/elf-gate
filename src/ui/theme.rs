use ratatui::style::{Color, Modifier, Style};

/// All colors live here; widgets never hardcode them.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub fg: Color,
    pub muted: Color,
    pub accent: Color,
    pub good: Color,
    pub warn: Color,
    pub bad: Color,
    pub selection_bg: Color,
}

impl Theme {
    pub fn dark() -> Self {
        Self {
            fg: Color::Gray,
            muted: Color::DarkGray,
            accent: Color::Cyan,
            good: Color::Green,
            warn: Color::Yellow,
            bad: Color::Red,
            selection_bg: Color::Rgb(40, 50, 70),
        }
    }

    pub fn text(&self) -> Style {
        Style::default().fg(self.fg)
    }
    pub fn muted(&self) -> Style {
        Style::default().fg(self.muted)
    }
    pub fn title(&self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }
    pub fn border(&self, focused: bool) -> Style {
        Style::default().fg(if focused { self.accent } else { self.muted })
    }
    pub fn selected(&self) -> Style {
        Style::default()
            .bg(self.selection_bg)
            .add_modifier(Modifier::BOLD)
    }
    pub fn good(&self) -> Style {
        Style::default().fg(self.good)
    }
    pub fn warn(&self) -> Style {
        Style::default().fg(self.warn)
    }
    pub fn bad(&self) -> Style {
        Style::default().fg(self.bad)
    }
}
