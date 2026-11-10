use crate::action::BINDINGS;
use crate::ui::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

pub fn render(f: &mut Frame, area: Rect, th: &Theme) {
    let mut lines: Vec<Line> = BINDINGS
        .iter()
        .filter(|b| !b.hidden)
        .map(|b| {
            Line::from(vec![
                Span::styled(format!("{:<18}", b.label), th.title()),
                Span::styled(b.desc, th.text()),
            ])
        })
        .collect();
    lines.push(Line::default());
    lines.push(Line::from(vec![
        Span::styled(format!("{:<18}", "[устар.]"), th.warn()),
        Span::styled(
            "устаревший транспорт (ws, grpc): работает, но Xray его не советует",
            th.text(),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled(format!("{:<18}", "серый, n/a"), th.muted()),
        Span::styled(
            "сервер не поддерживается или отвергнут Xray; причина в деталях",
            th.text(),
        ),
    ]));
    f.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title(Span::styled(" Справка (Esc - назад) ", th.title()))),
        area,
    );
}
