//! Privacy mode: nothing from the fixtures may reach the screen, on any screen.

use super::tests_support::draw;
use crate::action::Action;
use crate::app::tests::view_with;
use crate::app::{AppState, Conn, LinkState, Screen};
use crate::event::{Level, LinkEvent, LogLine};
use crate::model::rule::{Rule, RuleKind};
use crate::proto::{Alert, Cmd, Update};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PBK: &str = "4GObrWHDR0TyD84iQ06z24v4YBxQ69vxeG1MCqOyFlI";
const IP: &str = "212.147.241.154";
const HWID: &str = "9f86d081884c7d65";
const LINK: &str = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@212.147.241.154:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=4GObrWHDR0TyD84iQ06z24v4YBxQ69vxeG1MCqOyFlI&sid=ab12cd34&spx=%2Fsecret&type=grpc&serviceName=svcname&host=cdn.example.org#EtherVPN-FI";
const DOMAIN_LINK: &str = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@vpn.example.net:8443?security=tls&sni=vpn.example.net&type=ws&path=%2Fws-secret&host=vpn.example.net#Backup";

/// Everything that must never show.
const SECRETS: &[&str] = &[
    UUID,
    PBK,
    IP,
    HWID,
    "ab12cd34",
    "www.microsoft.com",
    "microsoft",
    "cdn.example",
    "svcname",
    "/secret",
    "vpn.example.net",
    "example.net",
    "ws-secret",
    "SECRETTOKEN",
    "panel.example.com",
    "vless://",
    "198.18.0.1",
    "203.0.113.77",
    "gstatic",
];

fn app() -> (AppState, UnboundedReceiver<Cmd>) {
    let (tx, rx) = unbounded_channel();
    let mut a = AppState::new(tx);
    let mut v = view_with(&[LINK, DOMAIN_LINK]);
    v.config.device.hwid = HWID.into();
    v.config.ui.privacy_mode = true;
    v.config.rules.push(Rule::new(RuleKind::Ip, IP));
    v.config
        .rules
        .push(Rule::new(RuleKind::Domain, "discord.com"));
    v.config.rules.push(Rule::new(RuleKind::Process, "Discord"));
    a.apply_view(v);
    a.link = LinkState::Up;
    a.selected = 1;
    for text in [
        "from tcp:198.18.0.1:39044 accepted tcp:212.147.241.154:443 [tun-in >> proxy]",
        "[Error] dial tcp 203.0.113.77:443: connect: connection refused",
        "from tcp:127.0.0.1:58460 accepted tcp:connectivitycheck.gstatic.com:80 [socks-in -> proxy]",
        "подписка не обновлена: https://panel.example.com/sub/SECRETTOKEN123456 недоступна",
    ] {
        a.on_link(LinkEvent::Update(Update::Log(LogLine {
            time: "00:00:00".into(),
            level: Level::Info,
            text: text.into(),
        })));
    }
    (a, rx)
}

fn press(a: &mut AppState, code: KeyCode) {
    a.handle_event(crate::event::Event::Key(KeyEvent::new(
        code,
        KeyModifiers::NONE,
    )));
}

fn clean(name: &str, frame: &str) {
    assert!(
        frame.contains("PRIVACY"),
        "{name}: the badge is missing:\n{frame}"
    );
    for s in SECRETS {
        assert!(
            !frame.contains(s),
            "{name}: `{s}` is on the screen:\n{frame}"
        );
    }
}

#[test]
fn no_screen_shows_a_secret_in_privacy_mode() {
    let mut cases: Vec<(&str, AppState)> = Vec::new();
    let (a, _rx) = app();
    cases.push(("main_server_details", a));
    let (mut a, _rx) = app();
    a.selected = 2;
    cases.push(("main_domain_server_details", a));
    let (mut a, _rx) = app();
    a.selected = 0;
    a.subs[0].is_remote = true;
    cases.push(("main_group", a));
    let (mut a, _rx) = app();
    a.conn = Conn::Error(format!("dial tcp {IP}:443: i/o timeout (203.0.113.77)"));
    cases.push(("main_error_in_the_status_bar", a));
    let (mut a, _rx) = app();
    a.focus = crate::app::Focus::Logs;
    cases.push(("main_logs_focus", a));
    let (mut a, _rx) = app();
    a.screen = Screen::LogsFull;
    cases.push(("logs_full", a));
    let (mut a, _rx) = app();
    a.screen = Screen::Rules;
    a.rules_cursor = a.rule_items().len() - 3;
    cases.push(("rules_with_the_servers_ip", a));
    let (mut a, _rx) = app();
    a.screen = Screen::Settings;
    cases.push(("settings_with_the_hwid", a));
    let (mut a, _rx) = app();
    a.screen = Screen::Settings;
    a.settings_cursor = a
        .settings_rows()
        .iter()
        .position(|r| r.0 == crate::app::SettingId::Hwid)
        .unwrap();
    a.handle_action(Action::Enter);
    cases.push(("settings_hwid_notice", a));
    let (mut a, _rx) = app();
    a.screen = Screen::Help;
    cases.push(("help", a));
    let (mut a, _rx) = app();
    a.on_link(LinkEvent::Update(Update::Alert(Alert::Error(format!(
        "Сервер недоступен по TCP: {IP}:443 (vpn.example.net, {UUID})"
    )))));
    cases.push(("error_dialog", a));
    let (mut a, _rx) = app();
    a.on_link(LinkEvent::Update(Update::Alert(Alert::Notice(format!(
        "Подписка https://panel.example.com/sub/SECRETTOKEN123456 вернула {IP}"
    )))));
    cases.push(("notice_dialog", a));
    let (mut a, _rx) = app();
    a.link = LinkState::Down(format!("не удалось подключиться к {IP}"));
    cases.push(("link_down", a));
    let (mut a, _rx) = app();
    a.subs[0].servers[0].unsupported = Some(format!("Xray отверг конфиг для {IP}"));
    a.selected = 1;
    cases.push(("unsupported_reason_in_details", a));
    for (name, mut a) in cases {
        let frame = draw(100, 32, &mut a);
        clean(name, &frame);
    }
    // And a few of them as snapshots, so a change in the masking is seen in review.
    let (mut a, _rx) = app();
    insta::assert_snapshot!("privacy_main_server_details", draw(100, 32, &mut a));
    let (mut a, _rx) = app();
    a.screen = Screen::Settings;
    insta::assert_snapshot!("privacy_settings", draw(100, 32, &mut a));
    let (mut a, _rx) = app();
    a.screen = Screen::LogsFull;
    insta::assert_snapshot!("privacy_logs", draw(100, 32, &mut a));
}

#[test]
fn what_is_not_a_secret_stays_visible() {
    let (mut a, _rx) = app();
    a.conn = Conn::Connected(1);
    a.subs[0].servers[0].tcp = crate::model::server::Ping::Ms(42);
    a.subs[0].servers[0].vpn = crate::model::server::Ping::Ms(97);
    a.subs[0].servers[0].ping_at = Some(crate::model::subscription::unix_now());
    let frame = draw(110, 32, &mut a);
    for keep in [
        "EtherVPN-FI",
        "Backup",
        "42 tcp",
        "97 vpn",
        "PROXY",
        "Подключено",
        ":443",
        "grpc",
        "Reality",
    ] {
        assert!(frame.contains(keep), "`{keep}` must stay:\n{frame}");
    }
    // User rules by domain and process are not secrets; the rule with the server's IP is hidden.
    a.screen = Screen::Rules;
    let frame = draw(110, 32, &mut a);
    assert!(
        frame.contains("discord.com") && frame.contains("Discord"),
        "{frame}"
    );
    assert!(!frame.contains(IP) && frame.contains("*.*.*.*"), "{frame}");
}

#[test]
fn without_privacy_mode_everything_shows_as_before() {
    let (mut a, _rx) = app();
    a.config.ui.privacy_mode = false;
    let frame = draw(110, 32, &mut a);
    assert!(frame.contains(IP) && !frame.contains("PRIVACY"), "{frame}");
}

#[test]
fn ctrl_p_and_the_setting_switch_the_mode_at_once_and_tell_the_daemon() {
    let (mut a, mut rx) = app();
    a.config.ui.privacy_mode = false;
    a.handle_event(crate::event::Event::Key(KeyEvent::new(
        KeyCode::Char('p'),
        KeyModifiers::CONTROL,
    )));
    assert!(a.privacy(), "the screen changes before the daemon answers");
    assert_eq!(
        rx.try_recv().unwrap(),
        Cmd::Set(crate::proto::Setting::PrivacyMode(true))
    );
    let frame = draw(100, 30, &mut a);
    assert!(frame.contains("PRIVACY"), "{frame}");
    assert!(crate::ui::hints::bar_text(&a, 200).contains("Ctrl+P прив.: вкл"));
    a.handle_event(crate::event::Event::Key(KeyEvent::new(
        KeyCode::Char('p'),
        KeyModifiers::CONTROL,
    )));
    assert!(!a.privacy());
    assert_eq!(
        rx.try_recv().unwrap(),
        Cmd::Set(crate::proto::Setting::PrivacyMode(false))
    );
    // The plain `p` is still the ping.
    press(&mut a, KeyCode::Char('p'));
    assert_eq!(rx.try_recv().unwrap(), Cmd::PingAll);
}

#[test]
fn a_link_is_typed_like_a_password_but_arrives_whole() {
    let (mut a, mut rx) = app();
    press(&mut a, KeyCode::Char('a'));
    for c in LINK.chars() {
        press(&mut a, KeyCode::Char(c));
    }
    let frame = draw(100, 32, &mut a);
    assert!(frame.contains('•'), "{frame}");
    assert!(frame.contains(&"•".repeat(30)), "the length shows");
    assert!(
        !frame.contains("vless") && !frame.contains(UUID) && !frame.contains(IP),
        "{frame}"
    );
    press(&mut a, KeyCode::Enter);
    assert_eq!(
        rx.try_recv().unwrap(),
        Cmd::AddLink(LINK.into()),
        "the real link is sent"
    );
}

#[test]
fn a_json_subscription_chain_shows_no_host_zone_and_no_home_directory() {
    use crate::model::fullconfig::tests::chain_dialer;
    let (tx, _rx) = unbounded_channel();
    let mut a = AppState::new(tx);
    let link = format!("xrayjson:{}", chain_dialer());
    let mut v = view_with(&[&link]);
    v.config.ui.privacy_mode = true;
    v.groups[0].name = "EtherVPN".into();
    v.groups[0].is_remote = true;
    a.apply_view(v);
    a.link = LinkState::Up;
    a.selected = 1;
    for text in [
        "Reading config: &{Name:/home/z3n/.local/state/elf-gate/run/xray.json Format:json}",
        "[Info] proxy/vless/outbound: failed to dial hop.example.com:8443 > dial tcp 203.0.113.9:8443: i/o timeout",
        "[Error] app/dns: lookup exit.example.com on 192.168.1.1:53: no such host",
        "xray: /home/z3n/bin/xray, ассеты: /home/z3n/bin (geoip.dat: есть)",
    ] {
        a.on_link(LinkEvent::Update(Update::Log(LogLine {
            time: "00:00:00".into(),
            level: Level::Info,
            text: text.into(),
        })));
    }
    a.config.tun.xray_path = "/home/z3n/bin/xray".into();
    let forbidden = [
        ".com",
        ".net",
        ".org",
        ".app",
        "example",
        "/home/",
        "z3n",
        "203.0.113.9",
        "192.168.1.1",
        UUID,
        PBK,
        "ab12",
        "www.example",
    ];
    let mut frames = Vec::new();
    for screen in [Screen::Main, Screen::LogsFull, Screen::Settings] {
        a.screen = screen;
        let frame = draw(120, 34, &mut a);
        for s in forbidden {
            assert!(
                !frame.contains(s),
                "{screen:?}: `{s}` is on the screen:\n{frame}"
            );
        }
        assert!(frame.contains("PRIVACY"));
        frames.push(frame);
    }
    // The chain's first hop is shown as hidden, its port and the chain size stay.
    a.screen = Screen::Main;
    let main = draw(120, 34, &mut a);
    assert!(
        main.contains("Цепочка:") && main.contains("Первый узел:") && main.contains("***:8443"),
        "{main}"
    );
    // And the home directory is a tilde.
    a.screen = Screen::LogsFull;
    let logs = draw(120, 34, &mut a);
    assert!(
        logs.contains("~/.local/state/elf-gate/run/xray.json") && logs.contains("xray: ~/bin/xray"),
        "{logs}"
    );
    insta::assert_snapshot!("privacy_json_chain_main", frames[0]);
    insta::assert_snapshot!("privacy_json_chain_logs", frames[1]);
    insta::assert_snapshot!("privacy_json_chain_settings", frames[2]);
}
