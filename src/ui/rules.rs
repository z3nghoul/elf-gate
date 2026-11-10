use crate::ui::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::Span;
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

pub fn render(f: &mut Frame, area: Rect, th: &Theme) {
    f.render_widget(
        Paragraph::new("Правила маршрутизации и пресеты - этап 7.\n\nEsc - назад")
            .style(th.muted())
            .block(Block::bordered().title(Span::styled(" Правила ", th.title()))),
        area,
    );
}
