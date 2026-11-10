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
fn states() -> Vec<(&'static str, AppState, (u16, u16))> {
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
    a.conn = Conn::Error("ядро завершилось".into());
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
        let last = frame.lines().last().unwrap().trim().to_string();
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
        assert!(
            last.chars().count() <= w as usize,
            "{name}: the bar overflows"
        );
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
        t.contains("Enter подключить")
            && t.contains("x удалить")
            && t.contains("f fp")
            && t.contains("b роль"),
        "{t}"
    );
    assert!(
        !t.contains("h скрытые") && !t.contains("d отключить"),
        "{t}"
    );
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
        t.contains("Enter отключить") && t.contains("d отключить"),
        "{t}"
    );
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
fn a_narrow_window_drops_the_least_important_keys_first_and_never_wraps() {
    let a = app(&[REALITY, TLS]);
    for width in [120usize, 80, 60, 40, 30, 20] {
        let t = bar_text(&a, width);
        assert!(t.chars().count() <= width, "{width}: `{t}` is too long");
        assert!(
            t.contains("? помощь") || width < 30,
            "{width}: help must stay in `{t}`"
        );
        assert!(
            t.contains("q/Q выход") || width < 30,
            "{width}: quit must stay in `{t}`"
        );
        if width <= 60 {
            assert!(t.contains('…'), "{width}: the cut must be shown in `{t}`");
        }
        if (50..=60).contains(&width) {
            assert!(t.contains("Enter"), "{width}: the main key stays in `{t}`");
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
