use crate::app::{AppState, Conn, Focus, Row, Screen};
use crate::model::server::Ping;
use crate::ui::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

pub fn render(f: &mut Frame, area: Rect, app: &mut AppState, th: &Theme) {
    let focused = app.screen == Screen::Main && app.focus == Focus::Servers;
    let connected_id = match app.conn {
        Conn::Connected(id) | Conn::Connecting(id) => Some(id),
        _ => None,
    };

    let rows = app.rows();
    if rows.is_empty() && app.filter.is_empty() {
        // First run: nothing to select yet, so tell the user what to do.
        let text = "Список серверов пуст.\n\nНажмите a, чтобы добавить сервер.\n(ссылка на сервер, а не на подписку)";
        f.render_widget(
            Paragraph::new(text)
                .style(th.text())
                .wrap(Wrap { trim: false })
                .block(
                    Block::bordered()
                        .title(Span::styled(" Серверы ", th.title()))
                        .border_style(th.border(focused)),
                ),
            area,
        );
        return;
    }
    let items: Vec<ListItem> = rows
        .iter()
        .map(|row| match *row {
            Row::Group(i) => {
                let sub = &app.subs[i];
                let arrow = if sub.collapsed { "▶" } else { "▼" };
                ListItem::new(Line::from(Span::styled(
                    format!("{arrow} {} ({})", sub.name, sub.servers.len()),
                    th.title(),
                )))
            }
            Row::Server(i, j) => {
                let s = &app.subs[i].servers[j];
                let marker = if Some(s.id) == connected_id {
                    "● "
                } else {
                    "  "
                };
                let ping_style = match s.ping {
                    Ping::Ms(ms) if ms < 80 => th.good(),
                    Ping::Ms(_) => th.warn(),
                    Ping::Timeout | Ping::Error => th.bad(),
                    _ => th.muted(),
                };
                if s.info_only {
                    // A title or a notice from the provider: shown, never selectable as a server.
                    return ListItem::new(Line::from(vec![
                        Span::styled("  ", th.muted()),
                        Span::styled(s.name.clone(), th.muted()),
                    ]));
                }
                let (name_style, ping_text, ping_style) = if s.is_supported() {
                    (th.text(), s.ping.label(), ping_style)
                } else {
                    (th.muted(), "n/a".to_string(), th.muted())
                };
                // Separate from incompatibility: the server works, but its transport is deprecated.
                let tag = if s.deprecated_transport().is_some() {
                    "[устар.]"
                } else {
                    ""
                };
                let name: String = s.name.chars().take(14).collect();
                ListItem::new(Line::from(vec![
                    Span::styled(marker, th.good()),
                    Span::styled(format!("{name:<14}"), name_style),
                    Span::styled(format!("{tag:<8}"), th.warn()),
                    Span::styled(format!("{ping_text:>8}"), ping_style),
                    Span::styled(
                        format!(
                            " {}",
                            if s.is_supported() && s.ping_at.is_some() {
                                s.ping_kind.short()
                            } else {
                                ""
                            }
                        ),
                        th.muted(),
                    ),
                ]))
            }
        })
        .collect();

    let mut title = String::from(" Серверы ");
    if app.filtering || !app.filter.is_empty() {
        title.push_str(&format!(
            "[/{}{}] ",
            app.filter,
            if app.filtering { "_" } else { "" }
        ));
    }

    let list = List::new(items)
        .block(
            Block::bordered()
                .title(Span::styled(title, th.title()))
                .border_style(th.border(focused)),
        )
        .highlight_symbol("> ")
        .highlight_style(th.selected());

    let sel = if rows.is_empty() {
        None
    } else {
        Some(app.selected.min(rows.len() - 1))
    };
    app.list_state.select(sel);
    f.render_stateful_widget(list, area, &mut app.list_state);
}
