//! The key bar: one line at the bottom that nothing else may cover. It shows the keys that work
//! on the current screen for the selected item, taken from the same table (`action::BINDINGS`)
//! that handles the keys and fills the help screen, so it cannot say what the keys do not do.

use crate::action::{scope, Action, Binding, BINDINGS};
use crate::app::{AppState, ConfirmKind, Conn, Focus, LinkState, Popup, Row, Screen, SettingId};
use crate::model::server::Security;
use crate::ui::hits::Target;
use crate::ui::theme::Theme;
use crossterm::event::{KeyCode, KeyModifiers};
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
    /// The key a click on the hint presses where there is no action to run (a dialog).
    pub press: Option<(KeyCode, KeyModifiers)>,
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
        press: b.keys.first().copied(),
    }
}

fn plain(key: &str, text: &str, prio: u8) -> Hint {
    Hint {
        key: key.into(),
        text: text.into(),
        prio,
        action: None,
        press: None,
    }
}

/// A hint of a dialog: a click presses `code`.
fn pressing(key: &str, text: &str, prio: u8, code: KeyCode) -> Hint {
    Hint {
        press: Some((code, KeyModifiers::NONE)),
        ..plain(key, text, prio)
    }
}

/// What the keys at the bottom of every screen say: help and quit.
pub fn tail() -> Vec<Hint> {
    vec![
        hint(Action::Help, binding(Action::Help).short()),
        Hint {
            key: format!(
                "{}/{}",
                binding(Action::Quit).bar,
                binding(Action::QuitAll).bar
            ),
            text: binding(Action::Quit).short(),
            prio: 1,
            action: Some(Action::Quit),
            press: None,
        },
    ]
}

/// Keys of an open dialog or input: they replace everything else (no other key works then).
fn modal_hints(app: &AppState) -> Option<Vec<Hint>> {
    if let Some(p) = &app.popup {
        return Some(match p {
            Popup::Select { .. } => vec![
                pressing("j/k", &crate::t!("hint.select"), 2, KeyCode::Down),
                pressing("Enter", &crate::t!("hint.apply"), 1, KeyCode::Enter),
                pressing("Esc", &crate::t!("hint.cancel"), 1, KeyCode::Esc),
            ],
            Popup::Processes { .. } => vec![
                pressing("↑↓", &crate::t!("hint.select"), 2, KeyCode::Down),
                pressing("Enter", &crate::t!("hint.apply"), 1, KeyCode::Enter),
                pressing("Esc", &crate::t!("hint.clear_close"), 1, KeyCode::Esc),
                pressing("PgUp/PgDn", &crate::t!("hint.page"), 4, KeyCode::PageDown),
                plain(&crate::t!("hint.text"), &crate::t!("hint.filter"), 3),
            ],
            Popup::Input { purpose, .. } => {
                let mut v = vec![
                    pressing("Enter", &crate::t!("hint.confirm"), 1, KeyCode::Enter),
                    pressing("Esc", &crate::t!("hint.cancel"), 1, KeyCode::Esc),
                ];
                // A separate element with its action: a mouse click can be hung on it later.
                if *purpose == crate::app::InputPurpose::Link {
                    v.push(hint(Action::Paste, crate::t!("hint.paste")));
                }
                v.push(pressing(
                    "Backspace",
                    &crate::t!("hint.erase"),
                    3,
                    KeyCode::Backspace,
                ));
                v
            }
            Popup::Confirm { kind, .. } => match kind {
                ConfirmKind::Paste(_) => vec![
                    pressing("Enter", &crate::t!("hint.apply"), 1, KeyCode::Enter),
                    pressing("Esc", &crate::t!("hint.cancel"), 1, KeyCode::Esc),
                ],
                ConfirmKind::Ask(_) => vec![
                    pressing("y/Enter", &crate::t!("hint.yes"), 1, KeyCode::Char('y')),
                    pressing("n/Esc", &crate::t!("hint.no"), 1, KeyCode::Char('n')),
                ],
                _ => vec![
                    pressing("y/Enter", &crate::t!("hint.yes"), 1, KeyCode::Char('y')),
                    pressing("n/Esc", &crate::t!("hint.no"), 1, KeyCode::Char('n')),
                ],
            },
            Popup::Update(_) => vec![
                pressing("↑↓", &crate::t!("hint.scroll"), 3, KeyCode::Down),
                pressing("s", &crate::t!("hint.skip_update"), 1, KeyCode::Char('s')),
                pressing(
                    &crate::t!("hint.any_key"),
                    &crate::t!("hint.close"),
                    1,
                    KeyCode::Esc,
                ),
            ],
            // A separate element with its action: a mouse click can be hung on it later.
            Popup::ConnError(_) => vec![
                hint(Action::Diag, crate::t!("hint.check")),
                pressing(
                    &crate::t!("hint.any_key"),
                    &crate::t!("hint.close"),
                    1,
                    KeyCode::Esc,
                ),
            ],
            Popup::Error(_) | Popup::Notice(_) => vec![pressing(
                &crate::t!("hint.any_key"),
                &crate::t!("hint.close"),
                1,
                KeyCode::Esc,
            )],
        });
    }
    if app.filtering {
        return Some(vec![
            pressing("Enter", &crate::t!("hint.accept_filter"), 1, KeyCode::Enter),
            pressing("Esc", &crate::t!("hint.reset"), 1, KeyCode::Esc),
            plain(&crate::t!("hint.text"), &crate::t!("hint.typing"), 3),
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
        Screen::Subscription => scope::SUB,
        Screen::LogsFull => scope::LOGS,
        Screen::Help => scope::HELP,
        Screen::Diag => scope::DIAG,
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
            Action::Down => Some(if logs_focus || app.screen == Screen::Help {
                crate::t!("hint.scroll")
            } else {
                crate::t!("hint.select")
            }),
            Action::PageDown | Action::Bottom => (logs_focus
                || !matches!(app.screen, Screen::Main | Screen::LogsFull))
            .then(|| b.short()),
            Action::FocusNext => Some(if app.screen == Screen::Settings {
                crate::t!("hint.section")
            } else {
                b.short()
            }),
            Action::Back => Some(b.short()),
            Action::Enter => match app.screen {
                Screen::Settings => {
                    let kind = app
                        .settings_rows()
                        .get(app.settings_cursor)
                        .map(|r| r.0.clone());
                    Some(match kind {
                        Some(
                            SettingId::SetSystemProxy
                            | SettingId::ProxyWithTun
                            | SettingId::ManageFirewall
                            | SettingId::AutoConnect
                            | SettingId::Autostart
                            | SettingId::VerboseLog
                            | SettingId::PingMode
                            | SettingId::Theme
                            | SettingId::TransparentBg
                            | SettingId::Mouse
                            | SettingId::SubDefaultHwid
                            | SettingId::LogLevel,
                        ) => crate::t!("hint.switch"),
                        Some(SettingId::Hwid) => crate::t!("hint.about_hwid"),
                        _ => crate::t!("hint.edit"),
                    })
                }
                Screen::Subscription => {
                    use crate::app::subscription::SubRow;
                    app.sub_fields().get(app.sub_cursor).and_then(|f| match f.row {
                        SubRow::UserAgent | SubRow::Hours => Some(crate::t!("hint.edit")),
                        SubRow::Hwid => Some(crate::t!("hint.switch")),
                        SubRow::Hidden => Some(crate::t!("hint.show_hidden")),
                        SubRow::Update | SubRow::Delete => Some(crate::t!("hint.run")),
                        SubRow::Name | SubRow::Url => None,
                    })
                }
                _ if !servers_focus => None,
                _ => match (row, server) {
                    (Some(Row::Group(i)), _) if app.subs[i].is_remote => {
                        Some(crate::t!("hint.open_sub"))
                    }
                    (Some(Row::Group(i)), _) => Some(if app.subs[i].collapsed {
                        crate::t!("hint.expand")
                    } else {
                        crate::t!("hint.fold")
                    }),
                    (_, Some(s)) if s.hidden => Some(crate::t!("hint.about_server")),
                    (_, Some(s)) if s.info_only => Some(crate::t!("hint.explain")),
                    (_, Some(s)) if !s.is_supported() => Some(crate::t!("hint.reason")),
                    (_, Some(s)) => Some(
                        if matches!(app.conn, Conn::Connected(c) | Conn::Connecting(c) if c == s.id)
                        {
                            crate::t!("hint.disconnect")
                        } else {
                            crate::t!("hint.connect")
                        },
                    ),
                    _ => None,
                },
            },
            // On the connected server Enter already disconnects: no second key for the same thing.
            Action::Disconnect => (on_main
                && connected
                && !server.is_some_and(
                    |s| matches!(app.conn, Conn::Connected(c) | Conn::Connecting(c) if c == s.id),
                ))
            .then(|| b.short()),
            Action::ToggleMode => on_main.then(|| match app.mode {
                crate::app::Mode::Proxy => "PROXY→TUN".to_string(),
                crate::app::Mode::Tun => "TUN→PROXY".to_string(),
            }),
            Action::PingAll => (on_main && any_servers).then(|| b.short()),
            Action::SortPing => (on_main && any_servers).then(|| {
                if app.sorted_by_ping {
                    crate::t!("hint.order")
                } else {
                    crate::t!("hint.by_ping")
                }
            }),
            Action::UpdateSubs => {
                (on_main && app.subs.iter().any(|g| g.is_remote)).then(|| b.short())
            }
            Action::Add => Some(if app.screen == Screen::Rules {
                crate::t!("hint.rule")
            } else {
                crate::t!("hint.add")
            }),
            Action::Delete => {
                if app.screen == Screen::Rules {
                    matches!(
                        app.rule_items().get(
                            app.rules_cursor
                                .min(app.rule_items().len().saturating_sub(1))
                        ),
                        Some(crate::app::RuleItem::Rule(_))
                    )
                    .then(|| crate::t!("hint.delete"))
                } else if !servers_focus {
                    None
                } else {
                    match (row, server) {
                        (Some(Row::Group(i)), _) => Some(if app.subs[i].is_remote {
                            crate::t!("hint.delete_sub")
                        } else {
                            crate::t!("hint.delete_group")
                        }),
                        (_, Some(s)) if s.hidden => Some(crate::t!("hint.restore")),
                        (Some(Row::Server(i, _)), Some(_)) if app.subs[i].is_remote => {
                            Some(crate::t!("hint.hide"))
                        }
                        (_, Some(_)) => Some(crate::t!("hint.delete")),
                        _ => None,
                    }
                }
            }
            Action::Rules if app.screen == Screen::Subscription => {
                use crate::app::subscription::Origin;
                app.sub_fields()
                    .get(app.sub_cursor)
                    .is_some_and(|f| f.origin == Origin::Own)
                    .then(|| crate::t!("hint.reset"))
            }
            Action::Rules | Action::Settings | Action::Logs => on_main.then(|| b.short()),
            Action::Edit => {
                (servers_focus && matches!(row, Some(Row::Group(i)) | Some(Row::Server(i, _)) if app.subs[i].is_remote))
                    .then(|| b.short())
            }
            Action::Fold => match row {
                Some(Row::Group(i)) if servers_focus => Some(if app.subs[i].collapsed {
                    crate::t!("hint.expand")
                } else {
                    crate::t!("hint.fold")
                }),
                _ => None,
            },
            Action::Filter => (on_main && any_servers).then(|| b.short()),
            Action::Fingerprint => (servers_focus
                && server.is_some_and(|s| !s.hidden && tls_like(s)))
            .then(|| b.short()),
            Action::Fragment => (servers_focus && server.is_some_and(|s| !s.hidden && tls_like(s)))
                .then(|| b.short()),
            Action::Role => (servers_focus
                && server.is_some_and(|s| !s.hidden && s.is_supported() && s.full.is_none()))
            .then(|| b.short()),
            Action::ShowHidden => (servers_focus
                && group.is_some_and(|g| g.servers.iter().any(|s| s.hidden)))
            .then(|| b.short()),
            Action::Privacy => Some(if app.privacy() {
                crate::t!("hint.privacy_on")
            } else {
                b.short()
            }),
            Action::Toggle | Action::RoutingMode => Some(b.short()),
            Action::Up
            | Action::PageUp
            | Action::Top
            | Action::FocusPrev
            | Action::Quit
            | Action::QuitAll
            | Action::Help
            | Action::Update
            | Action::Redraw => None,
            Action::DebugPanic | Action::Paste => None,
            Action::Diag => Some(if app.screen == Screen::Diag {
                crate::t!("hint.check_again")
            } else {
                b.short()
            }),
            Action::CopyReport => Some(b.short()),
        };
        if let Some(text) = text {
            out.push(Hint {
                key: b.bar.to_string(),
                text,
                prio: b.prio,
                action: Some(a),
                press: None,
            });
        }
    }
    out
}

/// Columns a hint takes in the bar: the keycap (the key with a space on each side), the
/// description right after it and a space before the next keycap. That is exactly what the bar
/// took before the keycaps (key, space, description, two spaces), so it never needs more rows.
pub(super) fn width_of(h: &Hint) -> usize {
    h.key.chars().count() + 2 + h.text.chars().count() + 1
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
        .map(|h| format!(" {} {}", h.key, h.text))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The bar as text, one string per row (tests and snapshots).
pub fn bar_lines(app: &AppState, width: usize) -> Vec<String> {
    rows(app, width)
        .iter()
        .map(|r| row_text(r).chars().take(width).collect())
        .collect()
}

/// All rows joined, each hint as `key text` (for substring checks: the keycap's spaces are
/// only how the bar is drawn).
pub fn bar_text(app: &AppState, width: usize) -> String {
    rows(app, width)
        .iter()
        .flatten()
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

/// What a click on the hint does: the key bound to its action on this screen, or the key it
/// stands for in a dialog.
fn click_target(app: &AppState, h: &Hint) -> Option<Target> {
    if app.popup.is_some() || app.filtering {
        h.press.map(|(code, mods)| Target::Key(code, mods))
    } else {
        h.action.map(Target::Action)
    }
}

pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme) {
    let rows = rows(app, area.width as usize);
    let mut lines: Vec<Line> = Vec::new();
    for (y, row) in rows.iter().take(area.height.max(1) as usize).enumerate() {
        let mut spans = Vec::new();
        let mut x = area.x;
        for (i, h) in row.iter().enumerate() {
            if i > 0 {
                spans.push(Span::raw(" "));
                x += 1;
            }
            let width = (width_of(h) - 1) as u16;
            let rect = Rect::new(x, area.y + y as u16, width, 1);
            let target = click_target(app, h);
            if let Some(t) = target {
                app.hits.click(rect, t);
            }
            // The pointer on a clickable hint lights it; the mouse setting off lights nothing
            // (the map is empty then, see `AppState::handle_mouse`).
            let lit = target.is_some() && app.config.ui.mouse && app.hits.is_hover(rect);
            let (cap, text) = if lit {
                (th.hover(), th.hover())
            } else {
                (th.keycap(), th.text())
            };
            spans.push(Span::styled(format!(" {} ", h.key), cap));
            if !h.text.is_empty() {
                spans.push(Span::styled(h.text.clone(), text));
            }
            x += width;
        }
        lines.push(Line::from(spans));
    }
    f.render_widget(Paragraph::new(lines), area);
}
