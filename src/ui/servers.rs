use crate::app::{AppState, Conn, Focus, Row, Screen};
use crate::model::server::Ping;
use crate::ui::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

/// `31 tcp · 98 vpn`; with no room for both (a narrow column) only `98 vpn`, the tcp number
/// stays in the details.
pub fn active_ping_text(s: &crate::model::server::Server, room: usize) -> String {
    let num = |p: Ping| match p {
        Ping::Ms(ms) => ms.to_string(),
        Ping::Timeout => "timeout".to_string(),
        Ping::Error => "error".to_string(),
        Ping::Unknown | Ping::Pending => "-".to_string(),
    };
    let vpn = format!("{} vpn", num(s.vpn));
    let both = format!("{} tcp \u{b7} {vpn}", num(s.tcp));
    if both.chars().count() <= room {
        both
    } else {
        vpn
    }
}

pub fn render(f: &mut Frame, area: Rect, app: &mut AppState, th: &Theme) {
    let focused = app.screen == Screen::Main && app.focus == Focus::Servers;
    let connected_id = match app.conn {
        Conn::Connected(id) | Conn::Connecting(id) => Some(id),
        _ => None,
    };

    let rows = app.rows();
    if rows.is_empty() && app.filter.is_empty() {
        // First run: nothing to select yet, so tell the user what to do.
        let text = crate::t!("servers.empty");
        f.render_widget(
            Paragraph::new(text)
                .style(th.text())
                .wrap(Wrap { trim: false })
                .block(
                    Block::bordered()
                        .title(Span::styled(
                            format!(" {} ", crate::t!("panel.servers")),
                            th.title(),
                        ))
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
                let arrow = if sub.collapsed { "►" } else { "▼" };
                ListItem::new(Line::from(Span::styled(
                    {
                        let hidden = sub.servers.iter().filter(|s| s.hidden).count();
                        let shown = sub.servers.len() - hidden;
                        if hidden > 0 {
                            crate::t!(
                                "servers.group_hidden",
                                arrow = arrow,
                                name = app.group_title(&sub.name),
                                shown = shown,
                                hidden = hidden
                            )
                        } else {
                            format!("{arrow} {} ({shown})", app.group_title(&sub.name))
                        }
                    },
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
                if s.hidden {
                    return ListItem::new(Line::from(vec![
                        Span::styled("  ", th.muted()),
                        Span::styled(
                            crate::t!("servers.hidden_row", name = app.server_title(s)),
                            th.muted(),
                        ),
                    ]));
                }
                if s.info_only {
                    // A title or a notice from the provider: shown, never selectable as a server.
                    return ListItem::new(Line::from(vec![
                        Span::styled("  ", th.muted()),
                        Span::styled(app.server_title(s), th.muted()),
                    ]));
                }
                let (name_style, ping_text, ping_style) = if s.is_supported() {
                    (th.text(), s.ping.label(), ping_style)
                } else {
                    (th.muted(), "n/a".to_string(), th.muted())
                };
                // The name takes all the room up to the latency column; a deprecated transport is
                // marked by a dagger right after the name (the details say what it means).
                let title = app.server_title(s);
                let deprecated = s.deprecated_transport().is_some();
                let content_w = (area.width as usize).saturating_sub(4); // frame and "> "
                let right_w = 16usize.min(content_w.saturating_sub(2 + 8));
                let name_w = content_w.saturating_sub(2 + right_w + 1).max(4);
                let shown = crate::ui::text::cut(&title, name_w - usize::from(deprecated));
                let name_span = Span::styled(
                    crate::ui::text::pad(
                        &format!("{shown}{}", if deprecated { "\u{2020}" } else { "" }),
                        name_w,
                    ),
                    name_style,
                );
                let gap = Span::raw(" ");
                if matches!(app.conn, Conn::Connected(id) if id == s.id) && s.is_supported() {
                    // The connected server always shows the same two numbers, in the same
                    // format: the way to it (tcp) and through the tunnel (vpn). They never swap.
                    let style = match s.vpn {
                        Ping::Ms(ms) if ms < 300 => th.good(),
                        Ping::Ms(_) => th.warn(),
                        Ping::Timeout | Ping::Error => th.bad(),
                        _ => th.muted(),
                    };
                    let text = active_ping_text(s, right_w);
                    return ListItem::new(Line::from(vec![
                        Span::styled(marker, th.good()),
                        name_span,
                        gap,
                        Span::styled(format!("{text:>right_w$}", right_w = right_w), style),
                    ]));
                }
                // The kind always takes four columns, so the latency column is straight.
                let kind = if s.is_supported() && s.ping_at.is_some() {
                    s.ping_kind.short()
                } else {
                    ""
                };
                ListItem::new(Line::from(vec![
                    Span::styled(marker, th.good()),
                    name_span,
                    gap,
                    Span::raw(" ".repeat(right_w.saturating_sub(12))),
                    Span::styled(format!("{ping_text:>8}"), ping_style),
                    Span::styled(format!(" {kind:<3}"), th.muted()),
                ]))
            }
        })
        .collect();

    let mut title = format!(" {} ", crate::t!("panel.servers"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::server::{Ping, PingKind, Server};

    fn shape_is_fixed(text: &str) -> bool {
        let parts: Vec<&str> = text.split(" \u{b7} ").collect();
        parts.len() == 2
            && parts[0].ends_with(" tcp")
            && parts[1].ends_with(" vpn")
            && !parts[0].contains("vpn")
            && !parts[1].contains("tcp")
    }

    #[test]
    fn a_sequence_of_updates_never_changes_the_kind_shown_for_the_connected_server() {
        let mut s = Server::unsupported("l", "R1".into(), "x".into());
        let mut texts = Vec::new();
        let mut step = |s: &mut Server, f: &dyn Fn(&mut Server)| {
            f(s);
            let t = active_ping_text(s, 40);
            assert!(shape_is_fixed(&t), "{t}");
            texts.push(t);
        };
        // The first numbers arrive in any order, the format is the same from the start.
        step(&mut s, &|s| {
            s.apply_ping(Ping::Ms(31), PingKind::Tcp, true, 1)
        });
        step(&mut s, &|s| s.apply_vpn(Some(608), 3, 2));
        step(&mut s, &|s| {
            s.apply_ping(Ping::Ms(35), PingKind::Tcp, true, 3)
        });
        // A temporary-core measurement of the connected server changes nothing.
        step(&mut s, &|s| {
            s.apply_ping(Ping::Ms(900), PingKind::Tunnel, true, 4)
        });
        // A series that got nothing through keeps the previous number.
        step(&mut s, &|s| s.apply_vpn(None, 0, 5));
        step(&mut s, &|s| {
            s.apply_ping(Ping::Timeout, PingKind::Tcp, true, 6)
        });
        step(&mut s, &|s| s.apply_vpn(Some(98), 3, 7));
        assert_eq!(texts[1], "31 tcp \u{b7} 608 vpn");
        assert_eq!(texts[2], "35 tcp \u{b7} 608 vpn");
        assert_eq!(texts[3], "35 tcp \u{b7} 608 vpn");
        assert_eq!(texts[4], "35 tcp \u{b7} 608 vpn");
        assert_eq!(texts[5], "timeout tcp \u{b7} 608 vpn");
        assert_eq!(texts[6], "timeout tcp \u{b7} 98 vpn");
        // The main number stays the tunnel's one once it exists.
        assert_eq!((s.ping, s.ping_kind), (Ping::Ms(98), PingKind::Tunnel));
        // No room for both: only the tunnel number.
        assert_eq!(active_ping_text(&s, 8), "98 vpn");
        // Disconnected: the tunnel number is gone, the list goes back to the tcp one.
        s.drop_vpn();
        assert_eq!((s.vpn, s.ping_kind), (Ping::Unknown, PingKind::Tcp));
        assert_eq!(s.ping, Ping::Timeout);
    }
}
