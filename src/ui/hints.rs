//! The key bar: one line at the bottom that nothing else may cover. It shows the keys that work
//! on the current screen for the selected item, taken from the same table (`action::BINDINGS`)
//! that handles the keys and fills the help screen, so it cannot say what the keys do not do.

use crate::action::{scope, Action, Binding, BINDINGS};
use crate::app::{AppState, ConfirmKind, Conn, Focus, LinkState, Popup, Row, Screen, SettingId};
use crate::model::server::Security;
use crate::ui::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hint {
    pub key: String,
    pub text: String,
    /// 1 stays longest when the window is narrow.
    pub prio: u8,
    pub action: Option<Action>,
}

fn binding(action: Action) -> &'static Binding {
    BINDINGS
        .iter()
        .find(|b| b.action == action)
        .expect("every action has a binding")
}

fn hint(action: Action, text: impl Into<String>) -> Hint {
    let b = binding(action);
    Hint {
        key: b.bar.to_string(),
        text: text.into(),
        prio: b.prio,
        action: Some(action),
    }
}

fn plain(key: &str, text: &str, prio: u8) -> Hint {
    Hint {
        key: key.into(),
        text: text.into(),
        prio,
        action: None,
    }
}

/// What the keys at the bottom of every screen say: help and quit.
pub fn tail() -> Vec<Hint> {
    vec![
        hint(Action::Help, binding(Action::Help).short),
        Hint {
            key: format!(
                "{}/{}",
                binding(Action::Quit).bar,
                binding(Action::QuitAll).bar
            ),
            text: binding(Action::Quit).short.into(),
            prio: 1,
            action: Some(Action::Quit),
        },
    ]
}

/// Keys of an open dialog or input: they replace everything else (no other key works then).
fn modal_hints(app: &AppState) -> Option<Vec<Hint>> {
    if let Some(p) = &app.popup {
        return Some(match p {
            Popup::Select { .. } => vec![
                plain("j/k", "выбор", 2),
                plain("Enter", "применить", 1),
                plain("Esc", "отмена", 1),
            ],
            Popup::Input { .. } => vec![
                plain("Enter", "подтвердить", 1),
                plain("Esc", "отмена", 1),
                plain("Backspace", "стереть", 3),
            ],
            Popup::Confirm { kind, .. } => match kind {
                ConfirmKind::Ask(_) => vec![plain("y/Enter", "да", 1), plain("n/Esc", "нет", 1)],
                _ => vec![plain("y/Enter", "да", 1), plain("n/Esc", "нет", 1)],
            },
            Popup::Error(_) | Popup::Notice(_) => vec![plain("любая клавиша", "закрыть", 1)],
        });
    }
    if app.filtering {
        return Some(vec![
            plain("Enter", "принять фильтр", 1),
            plain("Esc", "сбросить", 1),
            plain("текст", "ввод", 3),
        ]);
    }
    None
}

fn tls_like(s: &crate::model::server::Server) -> bool {
    s.is_supported() && s.full.is_none() && matches!(s.security, Security::Tls | Security::Reality)
}

/// The keys that work now, in table order.
pub fn hints(app: &AppState) -> Vec<Hint> {
    if let Some(h) = modal_hints(app) {
        return h;
    }
    // Without the background part no command can be carried out: only moving around works.
    let link_up = app.link == LinkState::Up;
    let sc = match app.screen {
        Screen::Main => scope::MAIN,
        Screen::Rules => scope::RULES,
        Screen::Settings => scope::SETTINGS,
        Screen::LogsFull => scope::LOGS,
        Screen::Help => scope::HELP,
    };
    let on_main = app.screen == Screen::Main;
    let row = app.selected_row();
    let server = app.selected_server();
    let group = match row {
        Some(Row::Group(i)) | Some(Row::Server(i, _)) => app.subs.get(i),
        None => None,
    };
    let logs_focus = app.screen == Screen::LogsFull || (on_main && app.focus == Focus::Logs);
    let servers_focus = on_main && app.focus == Focus::Servers;
    let any_servers = !app.subs.is_empty();
    let connected = !matches!(app.conn, Conn::Disconnected);

    let mut out = Vec::new();
    for b in BINDINGS
        .iter()
        .filter(|b| b.scopes & sc != 0 && !b.bar.is_empty())
    {
        let a = b.action;
        if matches!(a, Action::Quit | Action::QuitAll | Action::Help) {
            continue; // the tail
        }
        let command = !matches!(
            a,
            Action::Down
                | Action::PageDown
                | Action::Bottom
                | Action::FocusNext
                | Action::Back
                | Action::Help
        );
        if command && !link_up {
            continue;
        }
        let text: Option<String> = match a {
            Action::Down => Some(if logs_focus { "прокрутка" } else { "выбор" }.into()),
            Action::PageDown | Action::Bottom => logs_focus.then(|| b.short.to_string()),
            Action::FocusNext => Some(b.short.to_string()),
            Action::Back => Some(b.short.to_string()),
            Action::Enter => match app.screen {
                Screen::Settings => {
                    let kind = app.settings_rows().get(app.settings_cursor).map(|r| r.0.clone());
                    Some(match kind {
                        Some(
                            SettingId::SetSystemProxy
                            | SettingId::AutoConnect
                            | SettingId::Autostart
                            | SettingId::VerboseLog
                            | SettingId::PingMode
                            | SettingId::Theme
                            | SettingId::LogLevel,
                        ) => "переключить",
                        Some(SettingId::Hwid) => "о HWID",
                        _ => "изменить",
                    }
                    .into())
                }
                _ if !servers_focus => None,
                _ => match (row, server) {
                    (Some(Row::Group(i)), _) => Some(
                        if app.subs[i].collapsed { "развернуть" } else { "свернуть" }.into(),
                    ),
                    (_, Some(s)) if s.hidden => Some("о сервере".into()),
                    (_, Some(s)) if s.info_only => Some("пояснение".into()),
                    (_, Some(s)) if !s.is_supported() => Some("причина".into()),
                    (_, Some(s)) => Some(
                        if matches!(app.conn, Conn::Connected(c) | Conn::Connecting(c) if c == s.id) {
                            "отключ."
                        } else {
                            "подкл."
                        }
                        .into(),
                    ),
                    _ => None,
                },
            },
            // On the connected server Enter already disconnects: no second key for the same thing.
            Action::Disconnect => (on_main
                && connected
                && !server.is_some_and(|s| {
                    matches!(app.conn, Conn::Connected(c) | Conn::Connecting(c) if c == s.id)
                }))
            .then(|| b.short.to_string()),
            Action::ToggleMode => on_main.then(|| match app.mode {
                crate::app::Mode::Proxy => "PROXY→TUN".to_string(),
                crate::app::Mode::Tun => "TUN→PROXY".to_string(),
            }),
            Action::PingAll => (on_main && any_servers).then(|| b.short.to_string()),
            Action::SortPing => (on_main && any_servers).then(|| {
                if app.sorted_by_ping { "порядок" } else { "по пингу" }.to_string()
            }),
            Action::UpdateSubs => (on_main && app.subs.iter().any(|g| g.is_remote)).then(|| b.short.to_string()),
            Action::Add => Some(
                if app.screen == Screen::Rules { "правило" } else { "добавить" }.into(),
            ),
            Action::Delete => {
                if app.screen == Screen::Rules {
                    matches!(
                        app.rule_items().get(app.rules_cursor.min(app.rule_items().len().saturating_sub(1))),
                        Some(crate::app::RuleItem::Rule(_))
                    )
                    .then(|| "удалить".to_string())
                } else if !servers_focus {
                    None
                } else {
                    match (row, server) {
                        (Some(Row::Group(i)), _) => Some(
                            if app.subs[i].is_remote { "удал. подписку" } else { "удал. группу" }.into(),
                        ),
                        (_, Some(s)) if s.hidden => Some("вернуть".into()),
                        (Some(Row::Server(i, _)), Some(_)) if app.subs[i].is_remote => Some("скрыть".into()),
                        (_, Some(_)) => Some("удалить".into()),
                        _ => None,
                    }
                }
            }
            Action::Rules | Action::Settings | Action::Logs => on_main.then(|| b.short.to_string()),
            Action::Filter => (on_main && any_servers).then(|| b.short.to_string()),
            Action::Fingerprint => {
                (servers_focus && server.is_some_and(|s| !s.hidden && tls_like(s))).then(|| b.short.to_string())
            }
            Action::Fragment => {
                (servers_focus && server.is_some_and(|s| !s.hidden && tls_like(s))).then(|| b.short.to_string())
            }
            Action::Role => (servers_focus
                && server.is_some_and(|s| !s.hidden && s.is_supported() && s.full.is_none()))
            .then(|| b.short.to_string()),
            Action::ShowHidden => (servers_focus
                && group.is_some_and(|g| g.servers.iter().any(|s| s.hidden)))
            .then(|| b.short.to_string()),
            Action::Privacy => Some(if app.privacy() { "прив.: вкл" } else { "прив." }.into()),
            Action::Toggle | Action::RoutingMode => Some(b.short.to_string()),
            Action::Up
            | Action::PageUp
            | Action::Top
            | Action::FocusPrev
            | Action::Quit
            | Action::QuitAll
            | Action::Help => None,
            #[cfg(debug_assertions)]
            Action::DebugPanic => None,
        };
        if let Some(text) = text {
            out.push(Hint {
                key: b.bar.to_string(),
                text,
                prio: b.prio,
                action: Some(a),
            });
        }
    }
    out
}

fn width_of(h: &Hint) -> usize {
    h.key.chars().count() + 1 + h.text.chars().count() + 2
}

/// Most rows the key bar may take.
pub const MAX_ROWS: usize = 3;

/// The keys laid out in rows of `width` columns (at most [`MAX_ROWS`]). Whole hints only; when
/// even three rows are not enough the least important ones are left out, a `…` shows it, and
/// the help key always ends the last row.
pub fn layout_hints(list: Vec<Hint>, tail: Vec<Hint>, width: usize) -> Vec<Vec<Hint>> {
    let rows_needed = |items: &[Hint], ellipsis: bool| -> Vec<Vec<Hint>> {
        let mut all: Vec<Hint> = items.to_vec();
        if ellipsis {
            all.push(plain("…", "", 1));
        }
        all.extend(tail.iter().cloned());
        let mut rows: Vec<Vec<Hint>> = vec![Vec::new()];
        let mut used = 0;
        for h in all {
            let w = width_of(&h);
            if used + w > width && !rows.last().unwrap().is_empty() {
                rows.push(Vec::new());
                used = 0;
            }
            used += w;
            rows.last_mut().unwrap().push(h);
        }
        rows
    };
    let mut items = list;
    let mut dropped = false;
    loop {
        let rows = rows_needed(&items, dropped);
        if rows.len() <= MAX_ROWS || items.is_empty() {
            return rows;
        }
        // The least important (largest prio); among equals the one furthest right.
        let idx = items
            .iter()
            .enumerate()
            .max_by_key(|(i, h)| (h.prio, *i))
            .map(|(i, _)| i)
            .unwrap();
        items.remove(idx);
        dropped = true;
    }
}

/// The rows the key bar takes at this width (the screen reserves exactly this many lines).
pub fn rows(app: &AppState, width: usize) -> Vec<Vec<Hint>> {
    let modal = modal_hints(app).is_some();
    layout_hints(
        hints(app),
        if modal { Vec::new() } else { tail() },
        width.max(1),
    )
}

fn row_text(row: &[Hint]) -> String {
    row.iter()
        .map(|h| {
            if h.text.is_empty() {
                h.key.clone()
            } else {
                format!("{} {}", h.key, h.text)
            }
        })
        .collect::<Vec<_>>()
        .join("  ")
}

/// The bar as text, one string per row (tests and snapshots).
pub fn bar_lines(app: &AppState, width: usize) -> Vec<String> {
    rows(app, width)
        .iter()
        .map(|r| row_text(r).chars().take(width).collect())
        .collect()
}

/// All rows joined (for substring checks).
pub fn bar_text(app: &AppState, width: usize) -> String {
    bar_lines(app, width).join("  ")
}

pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme) {
    let lines: Vec<Line> = rows(app, area.width as usize)
        .iter()
        .take(area.height.max(1) as usize)
        .map(|row| {
            let mut spans = Vec::new();
            for (i, h) in row.iter().enumerate() {
                if i > 0 {
                    spans.push(Span::styled("  ", th.muted()));
                }
                spans.push(Span::styled(h.key.clone(), th.title()));
                if !h.text.is_empty() {
                    spans.push(Span::styled(format!(" {}", h.text), th.text()));
                }
            }
            Line::from(spans)
        })
        .collect();
    f.render_widget(Paragraph::new(lines), area);
}
