use crate::app::{AppState, Focus, Screen};
use crate::event::Level;
use crate::ui::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

pub fn render(f: &mut Frame, area: Rect, app: &mut AppState, th: &Theme) {
    let focused = match app.screen {
        Screen::LogsFull => true,
        Screen::Main => app.focus == Focus::Logs,
        _ => false,
    };
    let h = area.height.saturating_sub(2) as usize;
    app.log_view_h = h.max(1);

    let total = app.logs.len();
    app.log_scroll = app.log_scroll.min(total.saturating_sub(h));
    let end = total - app.log_scroll;
    let start = end.saturating_sub(h);

    let lines: Vec<Line> = app
        .logs
        .iter()
        .skip(start)
        .take(end - start)
        .map(|l| {
            let style = match l.level {
                Level::Info => th.text(),
                Level::Warning => th.warn(),
                Level::Error => th.bad(),
            };
            Line::from(vec![
                Span::styled(format!("{} ", l.time), th.muted()),
                Span::styled(l.text.clone(), style),
            ])
        })
        .collect();

    let mut title = String::from(" Логи ");
    if app.log_scroll > 0 {
        title.push_str(&format!("(↑{}, G - вниз) ", app.log_scroll));
    }
    f.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .title(Span::styled(title, th.title()))
                .border_style(th.border(focused)),
        ),
        area,
    );
}
