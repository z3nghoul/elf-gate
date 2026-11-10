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
        health: HealthState::Unknown,
        config: Config::default(),
        traffic: Traffic::default(),
        process_unresolved: 0,
        tray: false,
        autostart: false,
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
    let mut a = AppState::with_demo(tx);
    a.filter = "de-".into();
    let rows = a.rows();
    assert_eq!(rows.len(), 2); // group + DE-1
    assert!(matches!(rows[1], Row::Server(0, 0)));
}

#[tokio::test]
async fn collapsing_hides_servers_and_survives_a_new_view() {
    let (tx, _rx) = unbounded_channel();
    let mut a = AppState::with_demo(tx);
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
    let Some(Popup::Select { options, .. }) = &a.popup else {
        panic!("{:?}", a.popup)
    };
    let first = options[0].clone();
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
            Cmd::Set(crate::proto::Setting::Theme("light".into())),
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
    // (the same letters), and the Russian "da" for yes.
    let yes = ['y', 'Y', '\u{43d}', '\u{41d}', '\u{434}'];
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
    // Any other key keeps the question.
    let (mut a, _rx) = app_with(&[REALITY]);
    a.conn = Conn::Connected(1);
    press(&mut a, KeyCode::Char('q'));
    press(&mut a, KeyCode::Char('x'));
    assert!(matches!(a.popup, Some(Popup::Confirm { .. })));
}
