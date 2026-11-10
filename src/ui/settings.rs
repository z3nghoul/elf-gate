use crate::app::{AppState, Screen};
use crate::ui::theme::Theme;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme) {
    debug_assert_eq!(app.screen, Screen::Settings);
    let [list_area, foot] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(4)]).areas(area);
    let rows = app.settings_rows();
    let items: Vec<ListItem> = rows
        .iter()
        .map(|(id, label, value)| {
            let value = if app.privacy() && *id == crate::app::SettingId::Hwid {
                crate::redact::hwid(value)
            } else {
                app.mask(value)
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{label:<34}"), th.text()),
                Span::styled(value, th.title()),
            ]))
        })
        .collect();
    let mut state = ListState::default();
    state.select(Some(app.settings_cursor.min(rows.len().saturating_sub(1))));
    f.render_stateful_widget(
        List::new(items)
            .block(Block::bordered().title(Span::styled(
                format!(" {} ", crate::t!("panel.settings")),
                th.title(),
            )))
            .highlight_symbol("> ")
            .highlight_style(th.selected()),
        list_area,
        &mut state,
    );
    let tray = if app.tray {
        crate::t!("settings.tray_present")
    } else {
        crate::t!("settings.tray_absent")
    };
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(tray, th.muted())),
            Line::from(Span::styled(crate::t!("settings.footer"), th.text())),
        ])
        .wrap(ratatui::widgets::Wrap { trim: false })
        .block(Block::bordered()),
        foot,
    );
}
