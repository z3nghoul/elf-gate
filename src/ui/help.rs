use crate::action::BINDINGS;
use crate::ui::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

pub fn render(f: &mut Frame, area: Rect, th: &Theme) {
    let lines: Vec<Line> = BINDINGS
        .iter()
        .filter(|b| !b.hidden)
        .map(|b| {
            Line::from(vec![
                Span::styled(format!("{:<18}", b.label), th.title()),
                Span::styled(b.desc, th.text()),
            ])
        })
        .collect();
    f.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title(Span::styled(" Справка (Esc - назад) ", th.title()))),
        area,
    );
}
