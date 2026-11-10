//! Render snapshots of every screen and key state. In each of them the bottom line holds the
//! keys, and the keys it shows are the keys the table maps to the very same actions.

use super::hints::{bar_text, hints};
use super::tests_support::draw;
use crate::action::{map_key, Action};
use crate::app::tests::view_with;
use crate::app::{AppState, Conn, Focus, LinkState, Popup, Screen};
use crate::event::{Level, LinkEvent, LogLine};
use crate::model::rule::{Rule, RuleKind};
use crate::proto::{Alert, Ask, Update};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::mpsc::unbounded_channel;

const REALITY: &str =
    "vless://u@h.example.com:443?security=reality&sni=x.org&pbk=K&sid=ab&fp=chrome#R1";
const TLS: &str = "vless://u@h2.example.com:443?security=tls&sni=h2.example.com#Two";
const STUB: &str = "vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?security=none#Заглушка";

fn app(links: &[&str]) -> AppState {
    let (tx, _rx) = unbounded_channel();
    let mut a = AppState::new(tx);
    a.apply_view(view_with(links));
    a.link = LinkState::Up;
    a.selected = 1; // the first server (row 0 is the group)
    a
}

fn remote(mut a: AppState) -> AppState {
    a.subs[0].is_remote = true;
    a.subs[0].name = "EtherVPN".into();
    a
}

fn log(a: &mut AppState, text: &str) {
    a.on_link(LinkEvent::Update(Update::Log(LogLine {
        time: "00:00:00".into(),
        level: Level::Info,
        text: text.into(),
    })));
}

fn press(a: &mut AppState, code: KeyCode) {
    a.handle_event(crate::event::Event::Key(KeyEvent::new(
        code,
        KeyModifiers::NONE,
    )));
}

/// Every state: a name and the app in that state.
pub(super) fn states() -> Vec<(&'static str, AppState, (u16, u16))> {
    let big = (100, 30);
    let mut v: Vec<(&'static str, AppState, (u16, u16))> = Vec::new();

    v.push(("main_manual_server", app(&[REALITY, TLS]), big));
    v.push((
        "main_subscription_server",
        remote(app(&[REALITY, TLS])),
        big,
    ));
    let mut a = remote(app(&[REALITY]));
    a.selected = 0;
    v.push(("main_group_header", a, big));
    let mut a = remote(app(&[STUB, REALITY]));
    a.selected = 1;
    v.push(("main_placeholder_row", a, big));
    let mut a = remote(app(&[REALITY, TLS]));
    a.subs[0].servers[0].hidden = true;
    a.show_hidden.insert("EtherVPN".into());
    a.selected = 1;
    v.push(("main_hidden_server_shown", a, big));
    let mut a = app(&[]);
    a.selected = 0;
    v.push(("main_no_servers", a, big));
    let mut a = app(&[REALITY]);
    a.conn = Conn::Connecting(1);
    v.push(("main_connecting", a, big));
    let mut a = app(&[REALITY]);
    a.conn = Conn::Connected(1);
    log(&mut a, "[xray] started");
    v.push(("main_connected", a, big));
    let mut a = app(&[REALITY]);
    a.conn = Conn::Error("core exited".into());
    v.push(("main_error", a, big));
    let mut a = app(&[REALITY]);
    a.link = LinkState::Down("не отвечает".into());
    v.push(("link_down", a, big));
    let mut a = app(&[REALITY]);
    a.link = LinkState::Connecting;
    v.push(("link_connecting", a, big));
    let mut a = app(&[REALITY]);
    a.focus = Focus::Details;
    v.push(("main_details_focus", a, big));
    let mut a = app(&[REALITY]);
    a.focus = Focus::Logs;
    log(&mut a, "first line");
    log(&mut a, "second line");
    v.push(("main_logs_focus", a, big));

    let mut a = app(&[REALITY]);
    a.screen = Screen::Rules;
    a.rules_cursor = 0;
    v.push(("rules_on_a_preset", a, big));
    let mut a = app(&[REALITY]);
    a.config
        .rules
        .push(Rule::new(RuleKind::Domain, "example.com"));
    a.screen = Screen::Rules;
    a.rules_cursor = a.rule_items().len() - 1;
    v.push(("rules_on_a_user_rule", a, big));
    let mut a = app(&[REALITY]);
    a.screen = Screen::Settings;
    v.push(("settings_text_row", a, big));
    let mut a = app(&[REALITY]);
    a.screen = Screen::Settings;
    a.settings_cursor = 6; // the system proxy switch
    v.push(("settings_switch_row", a, big));
    let mut a = app(&[REALITY]);
    a.screen = Screen::LogsFull;
    log(&mut a, "a log line");
    v.push(("logs_full_screen", a, big));
    let mut a = app(&[REALITY]);
    a.screen = Screen::Help;
    v.push(("help_screen", a, big));

    let mut a = app(&[REALITY]);
    press(&mut a, KeyCode::Char('a'));
    v.push(("dialog_input", a, big));
    let mut a = app(&[REALITY]);
    press(&mut a, KeyCode::Char('f'));
    v.push(("dialog_select", a, big));
    let mut a = app(&[REALITY]);
    press(&mut a, KeyCode::Char('x'));
    v.push(("dialog_confirm", a, big));
    let mut a = app(&[REALITY]);
    a.on_link(LinkEvent::Update(Update::Alert(Alert::Error(
        "что-то пошло не так".into(),
    ))));
    v.push(("dialog_error", a, big));
    let mut a = app(&[REALITY]);
    a.on_link(LinkEvent::Update(Update::Alert(Alert::Notice(
        "к сведению".into(),
    ))));
    v.push(("dialog_notice", a, big));
    let mut a = app(&[REALITY]);
    a.on_link(LinkEvent::Update(Update::Alert(Alert::Ask {
        text: "Включить пресет?".into(),
        ask: Ask::PresetOffer(1),
    })));
    v.push(("dialog_question_from_the_daemon", a, big));
    let mut a = app(&[REALITY]);
    press(&mut a, KeyCode::Char('/'));
    v.push(("filter_input", a, big));

    v.push(("narrow_60_manual_server", app(&[REALITY, TLS]), (60, 24)));
    let mut a = remote(app(&[REALITY]));
    a.selected = 0;
    v.push(("narrow_60_group_header", a, (60, 24)));
    let mut a = app(&[REALITY]);
    a.screen = Screen::Rules;
    v.push(("narrow_60_rules", a, (60, 24)));
    v.push(("too_small_window", app(&[REALITY]), (50, 20)));
    v
}

#[test]
fn every_screen_and_state_has_a_key_bar_and_matches_its_snapshot() {
    for (name, mut a, (w, h)) in states() {
        let frame = draw(w, h, &mut a);
        // The bar may take up to three rows: look at all of them.
        let framed = name != "too_small_window";
        let n = super::hints::rows(&a, w as usize - if framed { 2 } else { 0 }).len();
        let frame_lines: Vec<&str> = frame.lines().collect();
        // The bar is framed: its rows sit above the bottom border (not in the too-small notice).
        let end = frame_lines.len() - usize::from(framed);
        let last = frame_lines[end - n..end].join(" ").trim().to_string();
        assert!(!last.is_empty(), "{name}: the key bar is empty:\n{frame}");
        let modal = matches!(name, n if n.starts_with("dialog_") || n == "filter_input");
        if !modal {
            assert!(
                last.contains("? помощь") || last.contains("помощь"),
                "{name}: no help key in `{last}`"
            );
            assert!(last.contains("q/Q"), "{name}: no quit key in `{last}`");
        } else {
            assert!(
                last.contains("Esc") || last.contains("любая клавиша"),
                "{name}: a dialog needs its own keys, got `{last}`"
            );
        }
        insta::assert_snapshot!(name, frame);
    }
}

#[test]
fn the_bar_shows_only_keys_that_work_for_the_selected_item() {
    let text = |a: &AppState| bar_text(a, 200);
    // A manual server: connect, delete, fp/role/fragment (it is Reality), no "hidden".
    let a = app(&[REALITY]);
    let t = text(&a);
    assert!(
        t.contains("Enter подкл.")
            && t.contains("x удалить")
            && t.contains("f fp")
            && t.contains("b роль"),
        "{t}"
    );
    assert!(!t.contains("h скрытые") && !t.contains("d отключ."), "{t}");
    // A subscription server: x hides.
    let t = text(&remote(app(&[REALITY])));
    assert!(t.contains("x скрыть") && t.contains("u подписки"), "{t}");
    // A placeholder: an explanation, no fp/role/fragment.
    let mut a = remote(app(&[STUB]));
    a.selected = 1;
    let t = text(&a);
    assert!(
        t.contains("Enter пояснение")
            && !t.contains("f fp")
            && !t.contains("b роль")
            && !t.contains("z фрагмент."),
        "{t}"
    );
    // Connected to it: Enter disconnects and d is offered.
    let mut a = app(&[REALITY]);
    a.conn = Conn::Connected(1);
    let t = text(&a);
    assert!(
        t.contains("Enter отключ.") && !t.contains("d отключ."),
        "{t}: Enter already disconnects, no second key for it"
    );
    // Connected to another server: Enter switches, d disconnects.
    let mut b = app(&[REALITY, TLS]);
    b.conn = Conn::Connected(2);
    let t = text(&b);
    assert!(t.contains("Enter подкл.") && t.contains("d отключ."), "{t}");
    // Nothing selectable: only adding (and the screens), no pings or deletes.
    let mut a = app(&[]);
    a.selected = 0;
    let t = text(&a);
    assert!(
        t.contains("a добавить") && !t.contains("p пинг") && !t.contains("x "),
        "{t}"
    );
    // Rules: a preset cannot be deleted, a user rule can.
    let mut a = app(&[REALITY]);
    a.screen = Screen::Rules;
    assert!(!text(&a).contains("x удалить") && text(&a).contains("Space вкл/выкл"));
    a.config
        .rules
        .push(Rule::new(RuleKind::Domain, "example.com"));
    a.rules_cursor = a.rule_items().len() - 1;
    assert!(text(&a).contains("x удалить"));
    // Without the background part no command is offered.
    let mut a = app(&[REALITY]);
    a.link = LinkState::Down("x".into());
    let t = text(&a);
    assert!(
        !t.contains("Enter") && !t.contains("p пинг") && t.contains("q/Q"),
        "{t}"
    );
}

#[test]
fn keys_wrap_to_more_rows_before_anything_is_dropped() {
    use super::hints::{bar_lines, rows, tail, MAX_ROWS};
    for (name, a, _) in states() {
        // Wide windows: nothing is left out, whatever the screen.
        for width in [120usize, 150] {
            let all = super::hints::hints(&a).len() + tail().len();
            let r = rows(&a, width);
            let shown: usize = r.iter().map(|row| row.len()).sum();
            let text = bar_lines(&a, width).join(" ");
            assert!(!text.contains('…'), "{name}@{width}: `{text}`");
            let modal = a.popup.is_some() || a.filtering;
            let expected = if modal {
                super::hints::hints(&a).len()
            } else {
                all
            };
            assert_eq!(
                shown, expected,
                "{name}@{width}: every key of the screen must be visible: `{text}`"
            );
        }
        // Every width: at most three rows, no row longer than the window, help stays last.
        for width in [150usize, 120, 80, 60, 40] {
            let lines = bar_lines(&a, width);
            assert!(
                lines.len() <= MAX_ROWS,
                "{name}@{width}: {} rows",
                lines.len()
            );
            assert!(
                lines.iter().all(|l| l.chars().count() <= width),
                "{name}@{width}"
            );
            if a.popup.is_none() && !a.filtering {
                let last = lines.last().unwrap();
                assert!(last.contains("q/Q"), "{name}@{width}: `{last}`");
            }
        }
    }
    // When even three rows do not hold everything the least important keys go, with a mark.
    let (_, a, _) = states()
        .into_iter()
        .find(|s| s.0 == "main_manual_server")
        .unwrap();
    let lines = bar_lines(&a, 30);
    assert_eq!(lines.len(), MAX_ROWS);
    assert!(
        lines.join(" ").contains('…') && lines.last().unwrap().contains("помощь"),
        "{lines:?}"
    );
}

#[test]
fn the_bar_snapshots_at_80_120_and_150_columns() {
    // The bottom rows only (the screens above them are snapshotted elsewhere).
    for width in [80u16, 120, 150] {
        for name in [
            "main_manual_server",
            "main_subscription_server",
            "main_connected",
            "rules_on_a_preset",
            "settings_text_row",
        ] {
            let (_, mut a, _) = states().into_iter().find(|s| s.0 == name).unwrap();
            let frame = draw(width, 30, &mut a);
            let n = super::hints::rows(&a, width as usize - 2).len();
            let lines: Vec<&str> = frame.lines().collect();
            let bar = lines[lines.len() - 1 - n..lines.len() - 1].join("\n");
            insta::assert_snapshot!(format!("bar_{name}_{width}"), bar);
        }
    }
}

#[test]
fn every_shown_key_is_the_key_the_table_maps_to_that_action() {
    use Action::*;
    let same = |a: Action, b: Action| {
        a == b
            || matches!(
                (a, b),
                (Down, Up)
                    | (Up, Down)
                    | (PageDown, PageUp)
                    | (PageUp, PageDown)
                    | (Bottom, Top)
                    | (Top, Bottom)
                    | (FocusNext, FocusPrev)
                    | (Quit, QuitAll)
            )
    };
    for (name, a, _) in states() {
        for h in hints(&a) {
            let Some(action) = h.action else { continue };
            // Single-character keys must really trigger that action.
            for part in h.key.split('/') {
                let mut chars = part.chars();
                let (Some(c), None) = (chars.next(), chars.next()) else {
                    continue;
                };
                let got = map_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
                assert!(
                    got.is_some_and(|g| same(g, action)),
                    "{name}: the bar says `{}` for {action:?} but the table maps it to {got:?}",
                    h.key
                );
            }
        }
    }
    // The popup keys the bar promises really close the popup.
    let mut a = app(&[REALITY]);
    a.on_link(LinkEvent::Update(Update::Alert(Alert::Notice("x".into()))));
    assert!(matches!(a.popup, Some(Popup::Notice(_))));
    press(&mut a, KeyCode::Char('z'));
    assert!(a.popup.is_none(), "any key closes a notice");
}

#[test]
fn the_status_line_wraps_into_rows_instead_of_being_cut() {
    use super::statusbar::rows;
    use super::theme::Theme;
    let th = Theme::by_name("dark");
    let mut a = app(&[REALITY]);
    a.conn = Conn::Connected(1);
    a.traffic.speed_up = 320;
    a.traffic.speed_down = 2_400;
    a.traffic.proxy_up = 305_200;
    a.traffic.direct_up = 76_400;
    a.status = Some("a message that is shown after the traffic".into());
    let text = |rs: &[ratatui::text::Line]| {
        rs.iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    };
    let wide = rows(&a, &th, 200);
    assert_eq!(wide.len(), 1, "{}", text(&wide));
    let narrow = rows(&a, &th, 60);
    assert!(narrow.len() >= 2 && narrow.len() <= 3, "{}", text(&narrow));
    for l in &narrow {
        assert!(l.width() <= 60, "{l}");
    }
    // Nothing is lost: every piece is on the screen in some row.
    let all = text(&narrow);
    for piece in ["PROXY", "320", "message"] {
        assert!(all.contains(piece), "{piece} missing:\n{all}");
    }
    // The frame grows with the rows and the panels give the space up.
    let frame = draw(60, 30, &mut a);
    assert!(frame.contains("message"), "{frame}");
}

#[test]
fn names_with_emoji_keep_the_list_and_the_frame_aligned() {
    use crate::model::server::Ping;
    let names = [
        "\u{1F1E9}\u{1F1EA}\u{26A1}\u{FE0F} #5 LTE \u{2014} \u{423}\u{43d}\u{438}\u{432}\u{435}\u{440}\u{441}\u{430}\u{43b}\u{44c}\u{43d}\u{44b}\u{439}",
        "\u{1F1FB}\u{1F1F3}\u{1F51E}\u{1F353} Auto | very long name \u{26A1}\u{26A1}\u{26A1}",
        "\u{2B07}\u{FE0F} Plain \u{2B07}\u{FE0F}",
        "\u{1F525}\u{1F525}",
    ];
    let links: Vec<String> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            format!(
                "vless://u@h{i}.example.com:443?security=tls&sni=x.org#{}",
                n
            )
        })
        .collect();
    let refs: Vec<&str> = links.iter().map(String::as_str).collect();
    let mut a = remote(app(&refs));
    for (i, s) in a.subs[0].servers.iter_mut().enumerate() {
        s.ping = Ping::Ms(30 + 17 * i as u32);
    }
    a.subs[0].servers[0].name = names[0].to_string();
    a.subs[0].servers[3].name = names[3].to_string();
    let frame = draw(100, 30, &mut a);
    // No emoji or joiner reaches the screen; the flag became its country code.
    for c in frame.chars() {
        assert!(
            !('\u{1F000}'..='\u{1FAFF}').contains(&c)
                && !matches!(c, '\u{26A1}' | '\u{FE0F}' | '\u{2B07}'),
            "{c:?} in\n{frame}"
        );
    }
    assert!(frame.contains("DE #5 LTE"), "{frame}");
    // The all-emoji name falls back to the address.
    assert!(frame.contains("h3.example.com:443"), "{frame}");
    // Every row has the same width and the latency column starts at one place.
    let lines: Vec<&str> = frame.lines().collect();
    let width = lines[0].chars().count();
    assert!(lines.iter().all(|l| l.chars().count() == width), "{frame}");
    let cols: Vec<usize> = lines
        .iter()
        .map(|l| l.chars().take(44).collect::<String>())
        .filter(|l| l.contains(" ms"))
        .map(|l| l.split(" ms").next().unwrap_or("").chars().count())
        .collect();
    assert!(
        cols.len() >= 4 && cols.windows(2).all(|w| w[0] == w[1]),
        "{cols:?}\n{frame}"
    );
    insta::assert_snapshot!("emoji_names_list", frame);
}

#[test]
fn the_name_column_takes_the_room_up_to_the_latency_and_a_dagger_marks_a_deprecated_transport() {
    use crate::model::server::Ping;
    let name = "DE #5 LTE \u{2014} \u{423}\u{43d}\u{438}\u{432}\u{435}\u{440}\u{441}\u{430}\u{43b}\u{44c}\u{43d}\u{44b}\u{439}";
    let links = [
        format!("vless://u@a.example.com:443?security=tls&sni=x.org#{name}"),
        format!("vless://u@b.example.com:443?security=tls&sni=x.org&type=ws&path=/#NL #1 LTE \u{2014} {name}"),
        "vless://u@c.example.com:443?security=tls&sni=x.org#Short".to_string(),
    ];
    let refs: Vec<&str> = links.iter().map(String::as_str).collect();
    for width in [100u16, 150] {
        let mut a = remote(app(&refs));
        for (i, s) in a.subs[0].servers.iter_mut().enumerate() {
            s.ping = Ping::Ms(40 + i as u32 * 25);
            // No time of the measurement: the details would show its age, and a snapshot
            // must not depend on the clock.
            s.ping_at = None;
        }
        let frame = draw(width, 30, &mut a);
        // The ping column starts at one place in every row of the list.
        let left: Vec<String> = frame
            .lines()
            .map(|l| l.chars().take(width as usize * 45 / 100).collect())
            .collect();
        let cols: Vec<usize> = left
            .iter()
            .filter(|l| l.contains(" ms"))
            .map(|l| l.split(" ms").next().unwrap().chars().count())
            .collect();
        assert!(
            cols.len() == 3 && cols.windows(2).all(|w| w[0] == w[1]),
            "{cols:?}\n{frame}"
        );
        if width == 150 {
            assert!(
                frame.contains(name),
                "the whole name must be visible:\n{frame}"
            );
        } else {
            assert!(frame.contains('\u{2026}'), "{frame}");
        }
        // The dagger is not cut away with the name, and no `[depr.]` label is left.
        assert!(frame.contains('\u{2020}'), "{frame}");
        assert!(
            !frame.contains("[depr.]") && !frame.contains("[\u{443}\u{441}\u{442}\u{430}\u{440}"),
            "{frame}"
        );
        insta::assert_snapshot!(format!("name_column_{width}"), frame);
    }
}
