use super::*;
use crate::parser::parse_link;
use crate::platform::mock::MockTunHost;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

const REALITY: &str =
    "vless://u@h.example.com:443?security=reality&sni=x.org&pbk=K&sid=ab&fp=chrome#R1";

pub(crate) fn view_with(links: &[&str]) -> View {
    let servers: Vec<crate::model::server::Server> = links
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let mut s = parse_link(l).unwrap().redacted();
            s.id = i as u64 + 1;
            s
        })
        .collect();
    let groups = if servers.is_empty() {
        Vec::new()
    } else {
        vec![Subscription {
            name: MANUAL_GROUP.into(),
            servers,
            collapsed: false,
            info: None,
            updated: None,
            is_remote: false,
        }]
    };
    View {
        groups,
        conn: Conn::Disconnected,
        mode: Mode::Proxy,
        conn_mode: Mode::Proxy,
        tun_active: false,
        proxy_active: false,
        tun_fallback: None,
        health: HealthState::Unknown,
        config: crate::test_support::config_ru(),
        traffic: Traffic::default(),
        process_unresolved: 0,
        tray: false,
        autostart: false,
        update: None,
        mock: false,
        pid: 1,
    }
}

fn app_with(links: &[&str]) -> (AppState, UnboundedReceiver<Cmd>) {
    let (tx, rx) = unbounded_channel();
    let mut a = AppState::new(tx).with_tun_host(Arc::new(MockTunHost::healthy()));
    a.apply_view(view_with(links));
    a.link = LinkState::Up;
    // The manual group header is row 0, the first server row 1.
    a.selected = 1;
    (a, rx)
}

fn press(a: &mut AppState, code: KeyCode) {
    a.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
}

fn sent(rx: &mut UnboundedReceiver<Cmd>) -> Vec<Cmd> {
    let mut v = Vec::new();
    while let Ok(c) = rx.try_recv() {
        v.push(c);
    }
    v
}

#[tokio::test]
async fn filter_shows_only_matches() {
    let (tx, _rx) = unbounded_channel();
    let mut a = AppState::with_demo(tx, crate::test_support::config_ru());
    a.filter = "de-".into();
    let rows = a.rows();
    assert_eq!(rows.len(), 2); // group + DE-1
    assert!(matches!(rows[1], Row::Server(0, 0)));
}

#[tokio::test]
async fn collapsing_hides_servers_and_survives_a_new_view() {
    let (tx, _rx) = unbounded_channel();
    let mut a = AppState::with_demo(tx, crate::test_support::config_ru());
    let all = a.rows().len();
    a.subs[0].collapsed = true;
    assert_eq!(a.rows().len(), all - a.subs[0].servers.len());
    let mut next = 0;
    let mut v = view_with(&[REALITY]);
    v.groups = crate::mock::subscriptions(&mut next);
    a.apply_view(v);
    assert!(
        a.subs[0].collapsed,
        "collapsed state is the interface's own"
    );
}

#[tokio::test]
async fn log_buffer_is_bounded() {
    let (mut a, _rx) = app_with(&[REALITY]);
    for i in 0..LOG_CAPACITY + 50 {
        a.log(Level::Info, format!("line {i}"));
    }
    assert_eq!(a.logs.len(), LOG_CAPACITY);
}

#[tokio::test]
async fn quit_asks_when_connected_and_quit_all_stops_the_daemon() {
    let (mut a, mut rx) = app_with(&[REALITY]);
    a.conn = Conn::Connected(1);
    a.handle_action(Action::Quit);
    assert!(!a.should_quit);
    assert!(matches!(a.popup, Some(Popup::Confirm { .. })));
    press(&mut a, KeyCode::Char('y'));
    assert!(a.should_quit);
    assert!(
        sent(&mut rx).is_empty(),
        "closing the interface sends nothing"
    );

    let (mut a, mut rx) = app_with(&[REALITY]);
    a.handle_action(Action::QuitAll);
    press(&mut a, KeyCode::Char('y'));
    assert!(a.should_quit);
    assert_eq!(sent(&mut rx), vec![Cmd::Shutdown]);
}

#[tokio::test]
async fn quit_is_immediate_when_disconnected() {
    let (mut a, _rx) = app_with(&[REALITY]);
    a.handle_action(Action::Quit);
    assert!(a.should_quit);
}

#[tokio::test]
async fn typing_a_link_sends_it_to_the_background_part() {
    let (mut a, mut rx) = app_with(&[]);
    a.handle_action(Action::Add);
    for c in "vless://x@y:1#z".chars() {
        press(&mut a, KeyCode::Char(c));
    }
    press(&mut a, KeyCode::Enter);
    assert!(a.popup.is_none());
    assert_eq!(sent(&mut rx), vec![Cmd::AddLink("vless://x@y:1#z".into())]);
}

#[tokio::test]
async fn enter_connects_and_a_greyed_out_server_is_explained_instead() {
    let (mut a, mut rx) = app_with(&[REALITY]);
    a.handle_action(Action::Enter);
    assert_eq!(sent(&mut rx), vec![Cmd::Connect(1)]);
    a.subs[0].servers[0].unsupported = Some("Xray отверг".into());
    a.handle_action(Action::Enter);
    assert!(matches!(a.popup, Some(Popup::Error(_))));
    assert!(sent(&mut rx).is_empty());
}

#[tokio::test]
async fn enter_on_the_connected_server_disconnects_it() {
    let (mut a, mut rx) = app_with(&[REALITY, "vless://u@h2.example.com:443?security=tls#Two"]);
    a.conn = Conn::Connected(1);
    a.handle_action(Action::Enter);
    assert_eq!(sent(&mut rx), vec![Cmd::Disconnect]);
    a.selected = 2; // another server: switch to it
    a.handle_action(Action::Enter);
    assert_eq!(sent(&mut rx), vec![Cmd::Connect(2)]);
}

#[tokio::test]
async fn delete_asks_first_then_names_the_server_or_group() {
    let (mut a, mut rx) = app_with(&[REALITY]);
    a.handle_action(Action::Delete);
    assert!(sent(&mut rx).is_empty());
    press(&mut a, KeyCode::Char('y'));
    assert_eq!(sent(&mut rx), vec![Cmd::DeleteServer(1)]);
    a.selected = 0;
    a.handle_action(Action::Delete);
    press(&mut a, KeyCode::Char('y'));
    assert_eq!(sent(&mut rx), vec![Cmd::DeleteGroup(MANUAL_GROUP.into())]);
}

#[tokio::test]
async fn fingerprint_menu_sends_the_choice_and_escape_changes_nothing() {
    let (mut a, mut rx) = app_with(&[REALITY]);
    a.handle_action(Action::Fingerprint);
    let Some(Popup::Select {
        options, selected, ..
    }) = &a.popup
    else {
        panic!("menu expected, got {:?}", a.popup)
    };
    assert_eq!(options[0], "как в ссылке (chrome)");
    assert_eq!(&options[1..], FINGERPRINTS);
    assert_eq!(*selected, 0);
    press(&mut a, KeyCode::Down);
    press(&mut a, KeyCode::Down); // firefox
    press(&mut a, KeyCode::Enter);
    assert_eq!(
        sent(&mut rx),
        vec![Cmd::SetFingerprint {
            id: 1,
            fp: Some("firefox".into())
        }]
    );
    a.handle_action(Action::Fingerprint);
    press(&mut a, KeyCode::Down);
    press(&mut a, KeyCode::Esc);
    assert!(a.popup.is_none() && sent(&mut rx).is_empty());
}

#[tokio::test]
async fn role_and_fragment_keys_send_commands() {
    let (mut a, mut rx) = app_with(&[REALITY]);
    a.handle_action(Action::Role);
    press(&mut a, KeyCode::Down); // primary
    press(&mut a, KeyCode::Enter);
    a.handle_action(Action::Fragment);
    assert_eq!(
        sent(&mut rx),
        vec![
            Cmd::SetRole {
                id: 1,
                role: Some(ServerRole::Primary)
            },
            Cmd::SetFragment { id: 1, on: true }
        ]
    );
}

#[tokio::test]
async fn fingerprint_and_fragment_are_for_tls_and_reality_only() {
    let (mut a, mut rx) = app_with(&["vless://u@10.0.0.5:443?security=none#Plain"]);
    a.handle_action(Action::Fingerprint);
    assert!(a.popup.is_none());
    assert!(a.status.as_deref().unwrap().contains("TLS или Reality"));
    a.handle_action(Action::Fragment);
    assert!(sent(&mut rx).is_empty());
}

#[tokio::test]
async fn the_fingerprint_hint_comes_from_the_connection_check() {
    let (mut a, _rx) = app_with(&[REALITY]);
    a.conn = Conn::Connected(1);
    a.health = HealthState::Ok(Duration::from_millis(80));
    assert_eq!(a.fp_hint(), None);
    a.health = HealthState::Failed("нет ответа".into());
    assert!(a.fp_hint().unwrap().contains("fp=firefox"));
    a.subs[0].servers[0].fp_override = Some("firefox".into());
    let hint = a.fp_hint().unwrap();
    assert!(
        !hint.contains("fp=firefox") && hint.contains("ключ"),
        "{hint}"
    );
}

#[tokio::test]
async fn alerts_wait_while_another_popup_is_open() {
    let (mut a, mut rx) = app_with(&[REALITY]);
    a.handle_action(Action::Add);
    a.on_link(LinkEvent::Update(Update::Alert(Alert::Error(
        "boom".into(),
    ))));
    assert!(
        matches!(a.popup, Some(Popup::Input { .. })),
        "typing is not hijacked"
    );
    press(&mut a, KeyCode::Esc);
    assert!(matches!(&a.popup, Some(Popup::Error(t)) if t == "boom"));
    press(&mut a, KeyCode::Char('x'));
    assert!(a.popup.is_none());

    // A question from the background part is answered with Answer.
    a.on_link(LinkEvent::Update(Update::Alert(Alert::Ask {
        text: "ok?".into(),
        ask: Ask::ApplyRules(1),
    })));
    press(&mut a, KeyCode::Char('n'));
    assert_eq!(
        sent(&mut rx),
        vec![Cmd::Answer {
            ask: Ask::ApplyRules(1),
            yes: false
        }]
    );
}

#[tokio::test]
async fn sorting_by_ping_reorders_rows_without_touching_the_data() {
    let (mut a, _rx) = app_with(&[REALITY, "vless://u@h2.example.com:443?security=tls#Two"]);
    a.subs[0].servers[0].ping = crate::model::server::Ping::Ms(90);
    a.subs[0].servers[1].ping = crate::model::server::Ping::Ms(20);
    a.handle_action(Action::SortPing);
    assert_eq!(a.rows()[1], Row::Server(0, 1));
    a.handle_action(Action::SortPing);
    assert_eq!(a.rows()[1], Row::Server(0, 0));
}

#[tokio::test]
async fn link_state_is_shown_in_the_status_bar() {
    let (mut a, _rx) = app_with(&[]);
    a.on_link(LinkEvent::Down("не отвечает".into()));
    let out = crate::ui::tests_support::draw(100, 30, &mut a);
    assert!(out.contains("Нет связи с фоновой частью"), "{out}");
    a.on_link(LinkEvent::Up);
    let out = crate::ui::tests_support::draw(100, 30, &mut a);
    assert!(!out.contains("Нет связи"), "{out}");
}

// ---------------- the rules screen ----------------

#[tokio::test]
async fn rules_keys_send_commands_with_the_right_targets() {
    let (mut a, mut rx) = app_with(&[REALITY]);
    a.config
        .rules
        .push(Rule::new(RuleKind::Domain, "example.com"));
    a.screen = Screen::Rules;
    a.rules_cursor = 1; // games-direct
    a.handle_action(Action::Toggle);
    a.rules_cursor = a.rule_items().len() - 1;
    a.handle_action(Action::Toggle);
    a.handle_action(Action::Delete);
    a.handle_action(Action::RoutingMode);
    assert_eq!(
        sent(&mut rx),
        vec![
            Cmd::ToggleRule(RuleRef::Preset("games-direct".into())),
            Cmd::ToggleRule(RuleRef::Rule(0)),
            Cmd::DeleteRule(0),
            Cmd::SetRouting(RoutingMode::Include),
        ]
    );
    a.rules_cursor = 0;
    a.handle_action(Action::Delete);
    assert!(a.status.as_deref().unwrap().contains("пресет"));
}

#[tokio::test]
async fn adding_a_rule_validates_first_and_then_sends() {
    let (mut a, mut rx) = app_with(&[REALITY]);
    a.screen = Screen::Rules;
    a.handle_action(Action::Add);
    press(&mut a, KeyCode::Down);
    press(&mut a, KeyCode::Down); // Домен
    press(&mut a, KeyCode::Enter);
    for c in "bad domain".chars() {
        press(&mut a, KeyCode::Char(c));
    }
    press(&mut a, KeyCode::Enter);
    assert!(matches!(&a.popup, Some(Popup::Error(t)) if t.contains("не добавлено")));
    assert!(sent(&mut rx).is_empty());
    press(&mut a, KeyCode::Esc);

    a.handle_action(Action::Add);
    press(&mut a, KeyCode::Down);
    press(&mut a, KeyCode::Down);
    press(&mut a, KeyCode::Enter);
    for c in "Example.com".chars() {
        press(&mut a, KeyCode::Char(c));
    }
    press(&mut a, KeyCode::Enter);
    assert_eq!(
        sent(&mut rx),
        vec![Cmd::AddRule {
            kind: RuleKind::Domain,
            value: "example.com".into()
        }]
    );
}

#[tokio::test]
async fn process_picker_lists_running_programs() {
    let (mut a, mut rx) = app_with(&[REALITY]);
    a.screen = Screen::Rules;
    a.handle_action(Action::Add);
    press(&mut a, KeyCode::Enter); // "выбрать из запущенных"
    let Some(Popup::Processes { items, .. }) = &a.popup else {
        panic!("{:?}", a.popup)
    };
    let first = items[0].0.clone();
    press(&mut a, KeyCode::Enter);
    assert_eq!(
        sent(&mut rx),
        vec![Cmd::AddRule {
            kind: RuleKind::Process,
            value: first
        }]
    );
}

#[tokio::test]
async fn rules_screen_renders_modes_and_inactive_notes() {
    let (mut a, _rx) = app_with(&[REALITY]);
    a.config.rules.push(Rule::new(RuleKind::Process, "obs"));
    a.screen = Screen::Rules;
    let out = crate::ui::tests_support::draw(100, 30, &mut a);
    assert!(out.contains("Режим маршрутизации: exclude"), "{out}");
    assert!(out.contains("правила по процессам неактивны"), "{out}");
    assert!(
        out.contains("Только Discord через VPN") && out.contains("(неактивен в режиме exclude)"),
        "{out}"
    );
    assert!(
        out.contains("процесс  obs") && out.contains("(только в TUN)"),
        "{out}"
    );
    a.mode = Mode::Tun;
    a.config.mode.routing = RoutingMode::Include;
    let out = crate::ui::tests_support::draw(100, 30, &mut a);
    assert!(
        out.contains("Режим маршрутизации: include")
            && out.contains("TUN, правила по процессам работают"),
        "{out}"
    );
}

#[tokio::test]
async fn vision_servers_are_flagged_as_not_needing_the_quic_preset() {
    let (mut a, _rx) = app_with(&[
        "vless://u@h.example.com:443?flow=xtls-rprx-vision&security=reality&sni=x.org&pbk=K&sid=ab#V",
    ]);
    assert!(a.vision_in_use());
    a.screen = Screen::Rules;
    a.rules_cursor = a
        .rule_items()
        .iter()
        .position(|i| matches!(i, RuleItem::Preset(id) if id == "block-quic"))
        .unwrap();
    let out = crate::ui::tests_support::draw(120, 40, &mut a);
    assert!(out.contains("UDP/443 закрыт ядром"), "{out}");
    a.screen = Screen::Main;
    let out = crate::ui::tests_support::draw(120, 40, &mut a);
    assert!(
        out.contains("QUIC:") && out.contains("flow=vision"),
        "{out}"
    );
}

// ---------------- settings ----------------

#[tokio::test]
async fn settings_rows_switch_cycle_and_edit() {
    let (mut a, mut rx) = app_with(&[REALITY]);
    a.screen = Screen::Settings;
    let idx =
        |a: &AppState, id: SettingId| a.settings_rows().iter().position(|r| r.0 == id).unwrap();

    a.settings_cursor = idx(&a, SettingId::AutoConnect);
    a.handle_action(Action::Enter);
    a.settings_cursor = idx(&a, SettingId::Theme);
    a.handle_action(Action::Enter);
    a.settings_cursor = idx(&a, SettingId::Autostart);
    a.handle_action(Action::Enter);
    assert_eq!(
        sent(&mut rx),
        vec![
            Cmd::Set(crate::proto::Setting::AutoConnect(true)),
            Cmd::Set(crate::proto::Setting::Theme("latte".into())),
            Cmd::Set(crate::proto::Setting::Autostart(true)),
        ]
    );

    a.settings_cursor = idx(&a, SettingId::SocksPort);
    a.handle_action(Action::Enter);
    assert!(matches!(a.popup, Some(Popup::Input { .. })));
    for _ in 0..5 {
        press(&mut a, KeyCode::Backspace);
    }
    for c in "2000".chars() {
        press(&mut a, KeyCode::Char(c));
    }
    press(&mut a, KeyCode::Enter);
    assert_eq!(
        sent(&mut rx),
        vec![Cmd::Set(crate::proto::Setting::SocksPort(2000))]
    );

    a.handle_action(Action::Enter);
    for _ in 0..5 {
        press(&mut a, KeyCode::Backspace);
    }
    press(&mut a, KeyCode::Char('x'));
    press(&mut a, KeyCode::Enter);
    assert!(matches!(&a.popup, Some(Popup::Error(t)) if t.contains("порт")));
    assert!(sent(&mut rx).is_empty());
}

#[tokio::test]
async fn the_light_theme_and_the_settings_screen_render() {
    let (mut a, _rx) = app_with(&[REALITY]);
    a.config.ui.theme = "light".into();
    a.screen = Screen::Settings;
    let out = crate::ui::tests_support::draw(100, 40, &mut a);
    assert!(
        out.contains("Запускать при входе в систему") && out.contains("Тема"),
        "{out}"
    );
}

#[tokio::test]
async fn the_kind_of_a_ping_is_shown_next_to_the_value() {
    use crate::model::server::{Ping, PingKind};
    let (mut a, _rx) = app_with(&[REALITY]);
    a.subs[0].servers[0].ping = Ping::Ms(42);
    a.subs[0].servers[0].ping_at = Some(crate::model::subscription::unix_now() - 30);
    let out = crate::ui::tests_support::draw(110, 30, &mut a);
    assert!(out.contains("42 ms tcp"), "{out}");
    assert!(
        out.contains("TCP до сервера") && out.contains("с назад"),
        "{out}"
    );
    a.subs[0].servers[0].ping_kind = PingKind::Tunnel;
    let out = crate::ui::tests_support::draw(110, 30, &mut a);
    assert!(
        out.contains("42 ms vpn") && out.contains("через туннель"),
        "{out}"
    );
}

// ---------------- hiding subscription servers ----------------

#[tokio::test]
async fn x_on_a_subscription_server_hides_it_and_h_shows_it_for_restoring() {
    let (mut a, mut rx) = app_with(&[REALITY, "vless://u@h2.example.com:443?security=tls#Two"]);
    a.subs[0].is_remote = true;
    a.conn = Conn::Connected(1);
    a.handle_action(Action::Delete);
    let Some(Popup::Confirm { text, .. }) = &a.popup else {
        panic!("{:?}", a.popup)
    };
    assert!(
        text.contains("Скрыть") && text.contains("подключение будет остановлено"),
        "{text}"
    );
    press(&mut a, KeyCode::Char('y'));
    assert_eq!(sent(&mut rx), vec![Cmd::DeleteServer(1)]);

    // The daemon answers with the server hidden: it is gone from the list...
    a.subs[0].servers[0].hidden = true;
    assert_eq!(a.rows().len(), 2, "group + the one visible server");
    // ...until h on the subscription shows it greyed; x then offers to restore it.
    a.selected = 0;
    a.handle_action(Action::ShowHidden);
    assert_eq!(a.rows().len(), 3);
    a.selected = 1;
    a.handle_action(Action::Delete);
    assert!(matches!(&a.popup, Some(Popup::Confirm { text, .. }) if text.contains("Вернуть")));
    press(&mut a, KeyCode::Char('y'));
    assert_eq!(sent(&mut rx), vec![Cmd::UnhideServer(1)]);
}

#[tokio::test]
async fn an_empty_subscription_can_be_selected_and_deleted() {
    let (mut a, mut rx) = app_with(&[REALITY]);
    a.subs[0].is_remote = true;
    a.subs[0].servers.clear();
    a.selected = 0;
    assert_eq!(a.rows(), vec![Row::Group(0)]);
    a.handle_action(Action::Delete);
    press(&mut a, KeyCode::Char('y'));
    assert_eq!(sent(&mut rx), vec![Cmd::DeleteGroup(MANUAL_GROUP.into())]);
}

#[tokio::test]
async fn the_details_count_connections_without_a_known_process() {
    let (mut a, _rx) = app_with(&[REALITY]);
    a.conn = Conn::Connected(1);
    a.process_unresolved = 37;
    let out = crate::ui::tests_support::draw(110, 40, &mut a);
    assert!(out.contains("не определён процесс: 37 соединений"), "{out}");
    a.process_unresolved = 0;
    assert!(!crate::ui::tests_support::draw(110, 40, &mut a).contains("не определён процесс"));
}

#[tokio::test]
async fn a_status_message_goes_away_by_itself() {
    let (mut a, _rx) = app_with(&[REALITY]);
    a.on_update(Update::Status("saved".into()));
    assert_eq!(a.status.as_deref(), Some("saved"));
    // A fresh message survives the ticks.
    a.handle_event(Event::Tick);
    assert_eq!(a.status.as_deref(), Some("saved"));
    // An old one is cleared by the next tick.
    a.status_since =
        Some(std::time::Instant::now() - STATUS_LIFETIME - std::time::Duration::from_secs(1));
    a.handle_event(Event::Tick);
    assert_eq!(a.status, None);
    // A newer message restarts the clock.
    a.on_update(Update::Status("again".into()));
    a.handle_event(Event::Tick);
    assert_eq!(a.status.as_deref(), Some("again"));
}

#[tokio::test]
async fn hotkeys_work_in_the_cyrillic_layouts_and_text_fields_take_the_characters_as_they_are() {
    // The key where Q sits, typed on the Russian layout: quit.
    let (mut a, _rx) = app_with(&[REALITY]);
    press(&mut a, KeyCode::Char('\u{439}'));
    assert!(a.should_quit);
    // The Ukrainian i is the S key: the settings screen.
    let (mut a, _rx) = app_with(&[REALITY]);
    press(&mut a, KeyCode::Char('\u{456}'));
    assert_eq!(a.screen, Screen::Settings);
    // Ctrl + the Russian key of P toggles the privacy mode.
    let (mut a, mut rx) = app_with(&[REALITY]);
    a.handle_key(KeyEvent::new(
        KeyCode::Char('\u{437}'),
        KeyModifiers::CONTROL,
    ));
    assert!(a.privacy());
    assert!(!sent(&mut rx).is_empty());
    // A link field: the Cyrillic stays Cyrillic.
    let (mut a, _rx) = app_with(&[]);
    a.handle_action(Action::Add);
    for c in "\u{439}\u{446}\u{443}\u{43a}\u{435}\u{43d}".chars() {
        press(&mut a, KeyCode::Char(c));
    }
    assert!(
        matches!(&a.popup, Some(Popup::Input { buf, .. }) if buf == "\u{439}\u{446}\u{443}\u{43a}\u{435}\u{43d}")
    );
    // The filter field too.
    let (mut a, _rx) = app_with(&[REALITY]);
    a.handle_action(Action::Filter);
    press(&mut a, KeyCode::Char('\u{439}'));
    press(&mut a, KeyCode::Char('\u{44b}'));
    assert_eq!(a.filter, "\u{439}\u{44b}");
}

#[tokio::test]
async fn confirm_dialogs_answer_to_the_y_and_n_keys_on_every_layout() {
    // (yes keys, no keys): Latin, Russian (the Y key is U+043D, the N key U+0442), Ukrainian
    // (the same letters): the keys, no meaning of the letters.
    let yes = ['y', 'Y', '\u{43d}', '\u{41d}'];
    let no = ['n', 'N', '\u{442}', '\u{422}'];
    for c in yes {
        let (mut a, _rx) = app_with(&[REALITY]);
        a.conn = Conn::Connected(1);
        // Q asks, the answer closes the interface.
        press(&mut a, KeyCode::Char('\u{439}'));
        assert!(matches!(a.popup, Some(Popup::Confirm { .. })), "{c:?}");
        press(&mut a, KeyCode::Char(c));
        assert!(a.should_quit, "`{c}` must confirm");
        assert!(a.popup.is_none());
    }
    for c in no {
        let (mut a, _rx) = app_with(&[REALITY]);
        a.conn = Conn::Connected(1);
        press(&mut a, KeyCode::Char('q'));
        press(&mut a, KeyCode::Char(c));
        assert!(!a.should_quit, "`{c}` must decline");
        assert!(a.popup.is_none());
    }
    // Any other key keeps the question, the Russian "da" (the L key) included.
    for c in ['x', '\u{434}', '\u{414}'] {
        let (mut a, _rx) = app_with(&[REALITY]);
        a.conn = Conn::Connected(1);
        press(&mut a, KeyCode::Char('q'));
        press(&mut a, KeyCode::Char(c));
        assert!(matches!(a.popup, Some(Popup::Confirm { .. })), "{c:?}");
        assert!(!a.should_quit);
    }
}

#[tokio::test]
async fn settings_are_grouped_and_hidden_by_platform() {
    use crate::app::settings::{section_of, Section};
    let (a, _rx) = app_with(&[REALITY]);
    let lin = a.settings_rows_for(false);
    let win = a.settings_rows_for(true);
    let has = |rows: &[(SettingId, String, String)], id: SettingId| rows.iter().any(|r| r.0 == id);
    assert!(has(&lin, SettingId::TunXrayPath) && !has(&win, SettingId::TunXrayPath));
    assert!(has(&win, SettingId::ManageFirewall) && !has(&lin, SettingId::ManageFirewall));
    // Sections come in the fixed order and each is one block.
    let secs: Vec<u8> = lin.iter().map(|r| section_of(&r.0) as u8).collect();
    assert!(secs.windows(2).all(|w| w[0] <= w[1]), "{secs:?}");
    assert_eq!(section_of(&lin[0].0), Section::Appearance);
}

#[tokio::test]
async fn settings_navigation_goes_over_every_row_and_sections_jump() {
    use crate::app::settings::section_of;
    let (mut a, _rx) = app_with(&[REALITY]);
    a.screen = Screen::Settings;
    let rows = a.settings_rows();
    // j visits each row once: headers are not rows, so the cursor never stops on one.
    let mut seen = vec![a.settings_cursor];
    for _ in 0..rows.len() + 3 {
        a.handle_action(Action::Down);
        if seen.last() != Some(&a.settings_cursor) {
            seen.push(a.settings_cursor);
        }
    }
    assert_eq!(seen, (0..rows.len()).collect::<Vec<_>>());
    // Tab goes to the first row of the next section, Shift+Tab to the start of this one, then back.
    a.settings_cursor = 0;
    a.handle_action(Action::FocusNext);
    assert_ne!(
        section_of(&rows[a.settings_cursor].0),
        section_of(&rows[0].0)
    );
    let first = a.settings_cursor;
    assert!(first == 0 || section_of(&rows[first - 1].0) != section_of(&rows[first].0));
    a.settings_cursor = first + 1;
    a.handle_action(Action::FocusPrev);
    assert_eq!(a.settings_cursor, first);
    a.handle_action(Action::FocusPrev);
    assert_eq!(a.settings_cursor, 0);
    // The last section: Tab stays.
    a.settings_cursor = rows.len() - 1;
    a.handle_action(Action::FocusNext);
    assert_eq!(a.settings_cursor, rows.len() - 1);
}

/// An app with two remote subscriptions, `Alpha` and `Beta`.
fn app_with_subs() -> (AppState, UnboundedReceiver<Cmd>) {
    let (mut a, rx) = app_with(&[REALITY]);
    for n in ["Alpha", "Beta"] {
        a.config
            .subscriptions
            .push(crate::storage::SubscriptionConfig {
                name: n.into(),
                url: format!("https://{}.example/***", n.to_lowercase()),
                ..Default::default()
            });
        a.subs.insert(
            0,
            crate::model::subscription::Subscription {
                name: n.into(),
                servers: Vec::new(),
                collapsed: false,
                info: None,
                updated: None,
                is_remote: true,
            },
        );
    }
    (a, rx)
}

#[tokio::test]
async fn subscription_screen_marks_defaults_and_overrides_and_resets() {
    use crate::app::subscription::{Origin, SubRow};
    let (mut a, mut rx) = app_with_subs();
    a.open_subscription("Alpha");
    assert_eq!(a.screen, Screen::Subscription);
    let origin = |a: &AppState, r: SubRow| {
        a.sub_fields()
            .into_iter()
            .find(|f| f.row == r)
            .unwrap()
            .origin
    };
    assert_eq!(origin(&a, SubRow::UserAgent), Origin::Default);
    a.config.subscriptions[0].user_agent = Some("my-ua".into());
    assert_eq!(origin(&a, SubRow::UserAgent), Origin::Own);
    a.sub_cursor = a
        .sub_fields()
        .iter()
        .position(|f| f.row == SubRow::UserAgent)
        .unwrap();
    a.handle_action(Action::Rules); // `r` on this screen resets
    assert_eq!(
        sent(&mut rx),
        vec![Cmd::Set(crate::proto::Setting::SubscriptionUserAgent {
            name: "Alpha".into(),
            value: None
        })]
    );
    // The HWID row: default -> the opposite -> default.
    a.sub_cursor = a
        .sub_fields()
        .iter()
        .position(|f| f.row == SubRow::Hwid)
        .unwrap();
    a.handle_action(Action::Enter);
    assert_eq!(
        sent(&mut rx),
        vec![Cmd::Set(crate::proto::Setting::SubscriptionHwid {
            name: "Alpha".into(),
            value: Some(false)
        })]
    );
}

#[tokio::test]
async fn enter_and_e_on_a_subscription_header_open_its_screen_and_u_offers_a_menu() {
    let (mut a, mut rx) = app_with_subs();
    a.selected = 0; // Beta's header (inserted first)
    assert!(matches!(a.selected_row(), Some(Row::Group(_))));
    a.handle_action(Action::Enter);
    assert_eq!(
        (a.screen, a.sub_name.as_str()),
        (Screen::Subscription, "Beta")
    );
    a.handle_action(Action::Back);
    assert_eq!(a.screen, Screen::Main);
    a.handle_action(Action::Edit);
    assert_eq!(a.screen, Screen::Subscription);
    a.handle_action(Action::Back);
    a.handle_action(Action::UpdateSubs);
    assert!(matches!(
        &a.popup,
        Some(Popup::Select { options, .. }) if options.len() == 3
    ));
    press(&mut a, KeyCode::Enter); // "update all"
    assert_eq!(sent(&mut rx), vec![Cmd::UpdateSubs]);
}

#[test]
fn an_override_touches_one_subscription_and_a_new_default_the_rest() {
    use crate::storage::{Config, SubscriptionConfig};
    let mut c = Config {
        subscriptions: vec![
            SubscriptionConfig {
                name: "A".into(),
                ..Default::default()
            },
            SubscriptionConfig {
                name: "B".into(),
                ..Default::default()
            },
        ],
        ..Config::default()
    };
    c.subscriptions[0].user_agent = Some("own".into());
    let d = &c.sub_defaults;
    assert_eq!(c.subscriptions[0].user_agent(d), "own");
    assert_eq!(
        c.subscriptions[1].user_agent(d),
        crate::net::fetch::DEFAULT_USER_AGENT
    );
    c.sub_defaults.user_agent = "new-default".into();
    c.sub_defaults.auto_update_hours = 3;
    let d = &c.sub_defaults;
    assert_eq!(
        c.subscriptions[0].user_agent(d),
        "own",
        "the override stays"
    );
    assert_eq!(c.subscriptions[1].user_agent(d), "new-default");
    assert_eq!(c.subscriptions[1].hours(d), 3);
    assert!(c.subscriptions[1].sends_hwid(d));
    // Files from before the defaults: the built-in values are not overrides.
    let old: Config = toml::from_str(
        "[[subscriptions]]\nname = \"X\"\nurl = \"u\"\nuser_agent = \"v2rayNG/1.10.4\"\nauto_update_hours = 12\n",
    )
    .unwrap();
    assert_eq!(old.subscriptions[0].auto_update_hours, None);
    let ser = toml::to_string(&old.subscriptions[0]).unwrap();
    assert!(!ser.contains("auto_update_hours"), "{ser}");
}

/// An app on the rules screen whose "pick a process" window is open over `names`.
fn process_picker(names: Vec<String>) -> (AppState, UnboundedReceiver<Cmd>) {
    let (tx, rx) = unbounded_channel();
    let host = MockTunHost {
        processes: names,
        ..MockTunHost::healthy()
    };
    let mut a = AppState::new(tx).with_tun_host(Arc::new(host));
    a.apply_view(view_with(&[REALITY]));
    a.link = LinkState::Up;
    a.screen = Screen::Rules;
    a.handle_action(Action::Add);
    press(&mut a, KeyCode::Enter);
    (a, rx)
}

fn fake_processes() -> Vec<String> {
    // 200 processes: 150 names, some of them twice, in no order.
    (0..200)
        .map(|i| format!("proc{:03}", (i * 7) % 150))
        .collect()
}

#[tokio::test]
async fn the_last_process_of_200_can_be_chosen_and_names_are_sorted_and_collapsed() {
    let (mut a, mut rx) = process_picker(fake_processes());
    let Some(Popup::Processes { items, .. }) = &a.popup else {
        panic!()
    };
    assert_eq!(items.len(), 150, "equal names are one row");
    assert!(items.windows(2).all(|w| w[0].0 <= w[1].0), "sorted by name");
    assert!(
        items.iter().any(|i| i.1 > 1),
        "with the number of processes"
    );
    let last = items.last().unwrap().0.clone();
    // Draw once so the window knows its height, then End and a draw: the last row is visible.
    let out = crate::ui::tests_support::draw(80, 24, &mut a);
    assert!(out.contains("proc000"), "{out}");
    press(&mut a, KeyCode::End);
    let out = crate::ui::tests_support::draw(80, 24, &mut a);
    assert!(out.contains(&last) && out.contains("> "), "{out}");
    assert!(out.contains("Esc"), "the keys stay visible: {out}");
    press(&mut a, KeyCode::Enter);
    assert_eq!(
        sent(&mut rx),
        vec![Cmd::AddRule {
            kind: RuleKind::Process,
            value: last
        }]
    );
}

#[tokio::test]
async fn page_down_walks_the_process_list_to_the_end() {
    let (mut a, _rx) = process_picker(fake_processes());
    for _ in 0..40 {
        crate::ui::tests_support::draw(80, 24, &mut a);
        press(&mut a, KeyCode::PageDown);
    }
    let Some(Popup::Processes {
        items, selected, ..
    }) = &a.popup
    else {
        panic!()
    };
    assert_eq!(*selected, items.len() - 1);
}

#[tokio::test]
async fn the_filter_narrows_the_list_and_escape_clears_it_before_closing() {
    let (mut a, mut rx) = process_picker(fake_processes());
    for c in "PROC14".chars() {
        press(&mut a, KeyCode::Char(c)); // case does not matter
    }
    let Some(Popup::Processes {
        items,
        filter,
        selected,
    }) = &a.popup
    else {
        panic!()
    };
    let shown = crate::app::process_matches(items, filter);
    assert_eq!((filter.as_str(), *selected), ("PROC14", 0));
    assert_eq!(shown.len(), 10, "proc140..proc149");
    press(&mut a, KeyCode::Backspace);
    let Some(Popup::Processes { filter, .. }) = &a.popup else {
        panic!()
    };
    assert_eq!(filter, "PROC1");
    press(&mut a, KeyCode::Esc); // clears the filter, the window stays
    let Some(Popup::Processes { filter, .. }) = &a.popup else {
        panic!("closed too early")
    };
    assert!(filter.is_empty());
    press(&mut a, KeyCode::Esc); // closes
    assert!(a.popup.is_none());
    assert!(sent(&mut rx).is_empty());
}

#[tokio::test]
async fn long_lists_scroll_with_the_selection_on_every_screen() {
    // The settings table: End reaches the last row on 80x24, whose rows are not all in view.
    let (mut a, _rx) = app_with(&[REALITY]);
    a.screen = Screen::Settings;
    let out = crate::ui::tests_support::draw(80, 24, &mut a);
    assert!(out.contains("Язык") && out.contains("ещё"), "{out}");
    let last = a.settings_rows().last().unwrap().1.clone();
    assert!(
        !out.contains(&last),
        "the last row is below the edge at first"
    );
    a.handle_action(Action::Bottom);
    let out = crate::ui::tests_support::draw(80, 24, &mut a);
    assert!(out.contains(&last), "{out}");
    a.handle_action(Action::Top);
    let out = crate::ui::tests_support::draw(80, 24, &mut a);
    assert!(
        out.contains("Внешний вид"),
        "the section header comes back: {out}"
    );
    // A selection moved past the edge by j moves the window.
    for _ in 0..25 {
        a.handle_action(Action::Down);
        crate::ui::tests_support::draw(80, 24, &mut a);
    }
    let sel = a.settings_rows()[a.settings_cursor].1.clone();
    let out = crate::ui::tests_support::draw(80, 24, &mut a);
    assert!(out.contains(&sel), "{out}");
}

#[tokio::test]
async fn help_on_80x24_is_whole_when_scrolled() {
    let (mut a, _rx) = app_with(&[REALITY]);
    a.screen = Screen::Help;
    let first = crate::ui::tests_support::draw(80, 24, &mut a);
    assert!(
        first.contains("ещё") && first.contains("q / Ctrl+C"),
        "{first}"
    );
    a.handle_action(Action::Bottom);
    let end = crate::ui::tests_support::draw(80, 24, &mut a);
    assert!(end.contains("серый, n/a"), "{end}");
    assert!(!end.contains("q / Ctrl+C"), "{end}");
    // PgDn moves by a page and never past the end.
    a.handle_action(Action::Top);
    for _ in 0..10 {
        crate::ui::tests_support::draw(80, 24, &mut a);
        a.handle_action(Action::PageDown);
    }
    let again = crate::ui::tests_support::draw(80, 24, &mut a);
    assert_eq!(again, end);
}

// ---------- paste from the clipboard ----------

const LINK_A: &str =
    "vless://11111111-1111-1111-1111-111111111111@one.example.com:443?security=tls#one";
const LINK_B: &str =
    "vless://22222222-2222-2222-2222-222222222222@two.example.com:443?security=tls#two";

fn paste_app(clip: crate::platform::mock::MockClipboard) -> (AppState, UnboundedReceiver<Cmd>) {
    let (a, rx) = app_with(&[]);
    (a.with_clipboard(Arc::new(clip)), rx)
}

fn ctrl_v(a: &mut AppState) {
    a.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::CONTROL));
}

fn confirm_text(a: &AppState) -> String {
    match &a.popup {
        Some(Popup::Confirm { text, .. }) => text.clone(),
        other => panic!("not a confirmation: {other:?}"),
    }
}

#[tokio::test]
async fn ctrl_v_in_the_add_dialog_asks_and_enter_adds_every_link() {
    let clip = crate::platform::mock::MockClipboard::with_text(&format!("{LINK_A}\n{LINK_B}"));
    let (mut a, mut rx) = paste_app(clip);
    a.handle_action(Action::Add);
    ctrl_v(&mut a);
    assert!(matches!(
        a.popup,
        Some(Popup::Confirm {
            kind: ConfirmKind::Paste(_),
            ..
        })
    ));
    assert!(sent(&mut rx).is_empty(), "nothing is added before Enter");
    press(&mut a, KeyCode::Enter);
    assert!(a.popup.is_none());
    assert_eq!(
        sent(&mut rx),
        vec![Cmd::AddLink(LINK_A.into()), Cmd::AddLink(LINK_B.into())]
    );
}

#[tokio::test]
async fn esc_cancels_the_paste() {
    let clip = crate::platform::mock::MockClipboard::with_text(LINK_A);
    let (mut a, mut rx) = paste_app(clip);
    a.handle_action(Action::Add);
    ctrl_v(&mut a);
    press(&mut a, KeyCode::Esc);
    assert!(a.popup.is_none());
    assert!(sent(&mut rx).is_empty());
}

#[tokio::test]
async fn a_subscription_url_is_sent_as_it_is() {
    let clip = crate::platform::mock::MockClipboard::with_text("https://sub.example.com/t/abc");
    let (mut a, mut rx) = paste_app(clip);
    a.handle_action(Action::Add);
    ctrl_v(&mut a);
    assert!(confirm_text(&a).contains("sub.example.com"));
    press(&mut a, KeyCode::Enter);
    assert_eq!(
        sent(&mut rx),
        vec![Cmd::AddLink("https://sub.example.com/t/abc".into())]
    );
}

#[tokio::test]
async fn duplicates_are_not_added_and_are_reported() {
    let clip = crate::platform::mock::MockClipboard::with_text(&format!("{LINK_A} {LINK_B}"));
    let (mut a, mut rx) = paste_app(clip);
    a.config.servers.push(crate::storage::ServerEntry {
        link: LINK_A.into(),
    });
    a.handle_action(Action::Add);
    ctrl_v(&mut a);
    let text = confirm_text(&a);
    assert!(
        text.contains(&crate::t!("paste.skipped", count = 1)),
        "{text}"
    );
    press(&mut a, KeyCode::Enter);
    assert_eq!(sent(&mut rx), vec![Cmd::AddLink(LINK_B.into())]);
}

#[tokio::test]
async fn everything_already_added_is_a_notice_and_sends_nothing() {
    let clip = crate::platform::mock::MockClipboard::with_text(LINK_A);
    let (mut a, mut rx) = paste_app(clip);
    a.config.servers.push(crate::storage::ServerEntry {
        link: LINK_A.into(),
    });
    a.handle_action(Action::Add);
    ctrl_v(&mut a);
    assert!(matches!(a.popup, Some(Popup::Notice(_))));
    assert!(sent(&mut rx).is_empty());
}

#[tokio::test]
async fn nothing_usable_is_a_short_message_and_the_dialog_stays() {
    for text in ["", "just some words", "ftp://x.example.com/f"] {
        let (mut a, mut rx) = paste_app(crate::platform::mock::MockClipboard::with_text(text));
        a.handle_action(Action::Add);
        ctrl_v(&mut a);
        assert!(
            matches!(
                a.popup,
                Some(Popup::Input {
                    purpose: InputPurpose::Link,
                    ..
                })
            ),
            "{text:?}"
        );
        assert_eq!(
            a.status.as_deref(),
            Some(crate::t!("paste.nothing").as_str())
        );
        assert!(sent(&mut rx).is_empty());
    }
}

#[tokio::test]
async fn an_unreachable_clipboard_keeps_the_manual_input_open() {
    let (mut a, mut rx) = paste_app(crate::platform::mock::MockClipboard::unavailable());
    a.handle_action(Action::Add);
    ctrl_v(&mut a);
    assert!(a
        .status
        .as_deref()
        .unwrap()
        .contains("no graphical session"));
    for c in "vless://x@y:1#z".chars() {
        press(&mut a, KeyCode::Char(c));
    }
    press(&mut a, KeyCode::Enter);
    assert_eq!(sent(&mut rx), vec![Cmd::AddLink("vless://x@y:1#z".into())]);
}

#[tokio::test]
async fn ctrl_v_works_on_the_cyrillic_layout_and_only_in_the_add_dialog() {
    let clip = crate::platform::mock::MockClipboard::with_text(LINK_A);
    let (mut a, _rx) = paste_app(clip);
    // Outside the dialog it does nothing.
    a.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::CONTROL));
    assert!(a.popup.is_none());
    a.handle_action(Action::Add);
    // The V key of the Russian layout types U+043C.
    a.handle_key(KeyEvent::new(
        KeyCode::Char('\u{43c}'),
        KeyModifiers::CONTROL,
    ));
    assert!(matches!(a.popup, Some(Popup::Confirm { .. })));
}

#[tokio::test]
async fn the_paste_confirmation_hides_the_subscription_host_in_privacy_mode() {
    let clip = crate::platform::mock::MockClipboard::with_text(&format!(
        "https://secret-sub.example.org/t/abc {LINK_A}"
    ));
    let (mut a, _rx) = paste_app(clip);
    a.config.ui.privacy_mode = true;
    a.handle_action(Action::Add);
    ctrl_v(&mut a);
    let shown = a.mask(&confirm_text(&a));
    for secret in ["secret-sub", "example.org", "one.example.com", "abc"] {
        assert!(!shown.contains(secret), "{secret} in {shown}");
    }
}

// ---------- the check screen ----------

use crate::diag::{CheckId, CheckResult, Fix, State};

fn check_result(id: CheckId, state: State, fix: Option<Fix>) -> CheckResult {
    CheckResult {
        id,
        state,
        detail: "found".into(),
        todo: (state == State::Problem).then(|| "do it".into()),
        fix,
    }
}

fn feed(a: &mut AppState, r: CheckResult) {
    a.on_link(LinkEvent::Update(Update::Check(r)));
}

#[tokio::test]
async fn the_check_key_opens_the_screen_and_asks_for_the_checks_of_the_selected_server() {
    let (mut a, mut rx) = app_with(&[REALITY]);
    a.handle_action(Action::Diag);
    assert_eq!(a.screen, Screen::Diag);
    assert_eq!(sent(&mut rx), vec![Cmd::RunChecks { server: Some(1) }]);
    assert!(a.diag.iter().all(|r| r.state == State::Waiting));
    feed(&mut a, check_result(CheckId::Dns, State::Running, None));
    assert!(a.diag_running(), "a check is running");
    // A second press while the checks run starts nothing.
    a.handle_action(Action::Diag);
    assert!(sent(&mut rx).is_empty());
    for id in CheckId::ALL {
        feed(&mut a, check_result(id, State::Ok, None));
    }
    assert!(!a.diag_running());
    a.handle_action(Action::Diag);
    assert_eq!(sent(&mut rx), vec![Cmd::RunChecks { server: Some(1) }]);
}

#[tokio::test]
async fn a_fix_is_asked_for_and_done_only_after_yes() {
    let (mut a, mut rx) = app_with(&[REALITY]);
    a.handle_action(Action::Diag);
    sent(&mut rx);
    for id in CheckId::ALL {
        feed(&mut a, check_result(id, State::Ok, None));
    }
    let row = CheckId::ALL
        .iter()
        .position(|i| *i == CheckId::SysProxy)
        .unwrap();
    feed(
        &mut a,
        check_result(CheckId::SysProxy, State::Problem, Some(Fix::ClearProxy)),
    );
    a.diag_cursor = row;
    press(&mut a, KeyCode::Enter);
    assert!(matches!(
        a.popup,
        Some(Popup::Confirm {
            kind: ConfirmKind::Fix(Fix::ClearProxy),
            ..
        })
    ));
    assert!(sent(&mut rx).is_empty(), "nothing before the answer");
    // No: nothing happens either.
    press(&mut a, KeyCode::Esc);
    assert!(a.popup.is_none());
    assert!(sent(&mut rx).is_empty());
    // Any other key keeps the question open and does nothing.
    press(&mut a, KeyCode::Enter);
    press(&mut a, KeyCode::Char('x'));
    assert!(sent(&mut rx).is_empty());
    press(&mut a, KeyCode::Char('y'));
    assert_eq!(
        sent(&mut rx),
        vec![
            Cmd::ApplyFix(Fix::ClearProxy),
            Cmd::RunChecks { server: Some(1) }
        ]
    );
}

#[tokio::test]
async fn enter_on_a_check_without_a_fix_does_nothing() {
    let (mut a, mut rx) = app_with(&[REALITY]);
    a.handle_action(Action::Diag);
    sent(&mut rx);
    feed(&mut a, check_result(CheckId::Core, State::Problem, None));
    a.diag_cursor = 0;
    press(&mut a, KeyCode::Enter);
    assert!(a.popup.is_none());
    assert!(sent(&mut rx).is_empty());
}

#[tokio::test]
async fn a_connection_error_window_opens_the_checks_on_c_and_closes_on_any_other_key() {
    let (mut a, mut rx) = app_with(&[REALITY]);
    a.on_link(LinkEvent::Update(Update::Alert(Alert::Failure(
        "no".into(),
    ))));
    assert!(matches!(a.popup, Some(Popup::ConnError(_))));
    press(&mut a, KeyCode::Char('c'));
    assert_eq!(a.screen, Screen::Diag);
    assert!(a.popup.is_none());
    assert_eq!(sent(&mut rx), vec![Cmd::RunChecks { server: Some(1) }]);

    let (mut a, mut rx) = app_with(&[REALITY]);
    a.on_link(LinkEvent::Update(Update::Alert(Alert::Failure(
        "no".into(),
    ))));
    press(&mut a, KeyCode::Char('q'));
    assert!(a.popup.is_none());
    assert_eq!(a.screen, Screen::Main);
    assert!(sent(&mut rx).is_empty());
}

fn report_app(
    clip: crate::platform::mock::MockClipboard,
    dir: &std::path::Path,
) -> (AppState, Arc<crate::platform::mock::MockClipboard>) {
    let (tx, _rx) = unbounded_channel();
    let clip = Arc::new(clip);
    let mut a = AppState::new(tx)
        .with_clipboard(clip.clone())
        .with_report_dir(dir.to_path_buf());
    a.apply_view(view_with(&[REALITY]));
    a.screen = Screen::Diag;
    a.log(Level::Info, "connecting to h.example.com:443");
    a.log(
        Level::Info,
        "link vless://u@h.example.com:443?security=reality&pbk=K&sid=ab",
    );
    for id in CheckId::ALL {
        let mut r = check_result(id, State::Ok, None);
        r.detail = "no answer from h.example.com:443".into();
        feed_to(&mut a, r);
    }
    (a, clip)
}

fn feed_to(a: &mut AppState, r: CheckResult) {
    a.on_link(LinkEvent::Update(Update::Check(r)));
}

#[tokio::test]
async fn the_report_goes_to_the_clipboard_without_the_addresses_of_the_servers() {
    let dir = crate::test_support::TempDir::new("report-clip");
    let (mut a, clip) = report_app(
        crate::platform::mock::MockClipboard::with_text(""),
        dir.path(),
    );
    a.handle_action(Action::CopyReport);
    let written = clip.written.lock().unwrap().clone();
    assert_eq!(written.len(), 1);
    for secret in ["h.example.com", "vless://u", "pbk=K", "sid=ab"] {
        assert!(!written[0].contains(secret), "{secret}:\n{}", written[0]);
    }
    assert!(written[0].contains(&crate::t!("diag.report_server", n = 1)));
    assert_eq!(a.status.as_deref(), Some(crate::t!("diag.copied").as_str()));
}

#[tokio::test]
async fn without_a_clipboard_the_report_is_a_file_in_the_log_folder_and_its_path_is_shown() {
    let dir = crate::test_support::TempDir::new("report-file");
    let (mut a, _clip) = report_app(
        crate::platform::mock::MockClipboard::unavailable(),
        dir.path(),
    );
    a.handle_action(Action::CopyReport);
    let files: Vec<_> = std::fs::read_dir(dir.path()).unwrap().flatten().collect();
    assert_eq!(files.len(), 1);
    let text = std::fs::read_to_string(files[0].path()).unwrap();
    assert!(!text.contains("h.example.com"));
    let status = a.status.clone().unwrap();
    assert!(status.contains("check-report-"), "{status}");
}

#[tokio::test]
async fn the_report_key_works_on_the_check_screen_only() {
    let dir = crate::test_support::TempDir::new("report-main");
    let (mut a, clip) = report_app(
        crate::platform::mock::MockClipboard::with_text(""),
        dir.path(),
    );
    a.screen = Screen::Main;
    a.handle_action(Action::CopyReport);
    assert!(clip.written.lock().unwrap().is_empty());
}
