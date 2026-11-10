use crate::app::{AppState, Popup};
use crate::ui::theme::Theme;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};
use ratatui::Frame;

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let [v] = Layout::vertical([Constraint::Length(h)])
        .flex(Flex::Center)
        .areas(area);
    let [r] = Layout::horizontal([Constraint::Length(w)])
        .flex(Flex::Center)
        .areas(v);
    r
}

pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme) {
    let Some(popup) = &app.popup else { return };
    let w = area.width.saturating_sub(10).clamp(30, 70);
    let (title, lines, border) = match popup {
        Popup::Input { title, buf } => (
            title.clone(),
            vec![
                Line::from(Span::styled(format!("{buf}_"), th.text())),
                Line::default(),
                Line::from(Span::styled("Enter - добавить, Esc - отмена", th.muted())),
            ],
            th.border(true),
        ),
        Popup::Confirm { text, .. } => (
            "Подтверждение".to_string(),
            vec![
                Line::from(Span::styled(text.clone(), th.text())),
                Line::default(),
                Line::from(Span::styled("y / Enter - да, n / Esc - нет", th.muted())),
            ],
            th.border(true),
        ),
        Popup::Error(msg) => (
            "Ошибка".to_string(),
            vec![
                Line::from(Span::styled(msg.clone(), th.bad())),
                Line::default(),
                Line::from(Span::styled("любая клавиша - закрыть", th.muted())),
            ],
            th.bad(),
        ),
    };
    let rect = centered(area, w, 7);
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::bordered()
                .title(Span::styled(format!(" {title} "), th.title()))
                .border_style(border),
        ),
        rect,
    );
}
