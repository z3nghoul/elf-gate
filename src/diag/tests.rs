use super::*;
use std::cell::RefCell;

/// A machine where everything is fine; a test breaks one thing.
struct Mock {
    windows: bool,
    core: Result<PathBuf, String>,
    other_core: Option<PathBuf>,
    other_version: Result<String, String>,
    caps: Option<String>,
    version: Result<String, String>,
    geo: (bool, bool),
    ping_url: bool,
    server: bool,
    tcp: Result<u32, TcpFail>,
    url: Result<u32, String>,
    dns_direct: bool,
    dns_via: Option<bool>,
    tun: Vec<Problem>,
    firewall: Option<Result<bool, String>>,
    stale: Option<String>,
    proxy: ProxyView,
    running: bool,
    connected: bool,
    ru_on: bool,
    vpn_ip: Result<String, String>,
    ru_ip: Result<String, String>,
    asked: RefCell<Vec<&'static str>>,
}

impl Mock {
    fn healthy() -> Self {
        Mock {
            windows: false,
            core: Ok(PathBuf::from("/opt/xray/xray")),
            other_core: None,
            other_version: Ok("26.1.0".into()),
            caps: None,
            version: Ok("26.1.0".into()),
            geo: (true, true),
            ping_url: true,
            server: true,
            tcp: Ok(40),
            url: Ok(120),
            dns_direct: true,
            dns_via: Some(true),
            tun: vec![],
            firewall: Some(Ok(true)),
            stale: None,
            proxy: ProxyView::NotOurs,
            running: true,
            connected: true,
            ru_on: true,
            vpn_ip: Ok("203.0.113.7".into()),
            ru_ip: Ok("198.51.100.9".into()),
            asked: RefCell::new(Vec::new()),
        }
    }
    fn windows() -> Self {
        Mock {
            windows: true,
            ..Self::healthy()
        }
    }
}

impl Env for Mock {
    fn windows(&self) -> bool {
        self.windows
    }
    fn core_binary(&self) -> Result<PathBuf, String> {
        self.core.clone()
    }
    fn other_core(&self) -> Option<PathBuf> {
        self.other_core.clone()
    }
    fn core_capabilities(&self, _: &Path) -> Option<String> {
        self.caps.clone()
    }
    async fn core_version(&self, path: &Path) -> Result<String, String> {
        if Some(path) == self.other_core.as_deref() {
            return self.other_version.clone();
        }
        self.version.clone()
    }
    fn geodata(&self, _: &Path) -> (bool, bool) {
        self.geo
    }
    fn ping_is_url(&self) -> bool {
        self.ping_url
    }
    fn has_server(&self) -> bool {
        self.server
    }
    async fn tcp(&self) -> Result<u32, TcpFail> {
        self.asked.borrow_mut().push("tcp");
        self.tcp.clone()
    }
    async fn url_ping(&self) -> Result<u32, String> {
        self.asked.borrow_mut().push("url");
        self.url.clone()
    }
    async fn dns_direct(&self, _: &str) -> bool {
        self.dns_direct
    }
    async fn dns_via_server(&self, _: &str) -> Option<bool> {
        self.dns_via
    }
    fn tun_problems(&self) -> Vec<Problem> {
        self.tun.clone()
    }
    fn explain(&self, p: &Problem) -> String {
        format!("{p:?}\nsecond line")
    }
    fn firewall_rules_in_place(&self) -> Option<Result<bool, String>> {
        self.firewall.clone()
    }
    fn stale_adapter(&self) -> Option<String> {
        self.stale.clone()
    }
    fn proxy_view(&self) -> ProxyView {
        self.proxy
    }
    fn core_running(&self) -> bool {
        self.running
    }
    fn connected(&self) -> bool {
        self.connected
    }
    fn ru_direct_on(&self) -> bool {
        self.ru_on
    }
    async fn ip_via_vpn(&self) -> Result<String, String> {
        self.vpn_ip.clone()
    }
    async fn ip_russian_site(&self) -> Result<String, String> {
        self.ru_ip.clone()
    }
}

async fn results(env: &Mock) -> Vec<CheckResult> {
    let mut seen: Vec<CheckResult> = Vec::new();
    run(env, |r| seen.push(r)).await;
    seen
}

async fn one(env: &Mock, id: CheckId) -> CheckResult {
    results(env)
        .await
        .into_iter()
        .rfind(|r| r.id == id)
        .unwrap()
}

fn is(r: &CheckResult, state: State) {
    assert_eq!(r.state, state, "{r:?}");
    // A problem says what to do; nothing else does.
    assert_eq!(r.todo.is_some(), state == State::Problem, "{r:?}");
    assert!(!r.detail.is_empty(), "{r:?}");
}

#[tokio::test]
async fn every_check_runs_in_turn_and_reports_running_before_its_result() {
    let seen = results(&Mock::healthy()).await;
    assert_eq!(seen.len(), CheckId::ALL.len() * 2);
    for (i, id) in CheckId::ALL.iter().enumerate() {
        assert_eq!((seen[2 * i].id, seen[2 * i].state), (*id, State::Running));
        assert_eq!(seen[2 * i + 1].id, *id);
        assert!(seen[2 * i + 1].state.finished());
    }
}

#[tokio::test]
async fn a_healthy_linux_machine_has_no_problem_and_skips_what_is_windows_only() {
    let seen = results(&Mock::healthy()).await;
    for r in seen.iter().filter(|r| r.state.finished()) {
        assert_ne!(r.state, State::Problem, "{r:?}");
        assert!(r.fix.is_none());
    }
    for id in [CheckId::Wintun, CheckId::Firewall, CheckId::Adapter] {
        is(&one(&Mock::healthy(), id).await, State::Skipped);
    }
}

#[tokio::test]
async fn core_ok_problem_and_a_fix_only_when_the_url_ping_needs_it() {
    let r = one(&Mock::healthy(), CheckId::Core).await;
    is(&r, State::Ok);
    assert!(r.detail.contains("26.1.0"));

    let mut m = Mock::healthy();
    m.core = Err("looked next to elf-gate".into());
    let r = one(&m, CheckId::Core).await;
    is(&r, State::Problem);
    assert_eq!(r.fix, Some(Fix::PingToTcp));
    m.ping_url = false;
    assert_eq!(one(&m, CheckId::Core).await.fix, None);

    let mut m = Mock::healthy();
    m.version = Err("exec format error".into());
    let r = one(&m, CheckId::Core).await;
    is(&r, State::Problem);
    assert_eq!(r.fix, None);
}

#[tokio::test]
async fn tun_core_is_checked_for_version_and_capability_and_both_versions_are_shown() {
    let mut m = Mock::healthy();
    m.other_core = Some(PathBuf::from("/home/u/xray"));
    m.caps = Some("/usr/local/lib/elf-gate/xray cap_net_admin=ep".into());
    let r = one(&m, CheckId::Core).await;
    is(&r, State::Ok);
    assert!(
        r.detail.contains("TUN") && r.detail.matches("26.1.0").count() == 2,
        "{r:?}"
    );

    m.other_version = Ok("26.2.0".into());
    let r = one(&m, CheckId::Core).await;
    is(&r, State::Problem);
    assert!(
        r.detail.contains("26.1.0") && r.detail.contains("26.2.0"),
        "{r:?}"
    );
    assert!(r.todo.as_deref().unwrap().contains("elf-gate-tun.sh"));

    m.other_version = Ok("26.1.0".into());
    m.caps = Some("/usr/local/lib/elf-gate/xray".into());
    is(&one(&m, CheckId::Core).await, State::Problem);
    m.caps = None;
    is(&one(&m, CheckId::Core).await, State::Ok);
}

#[tokio::test]
async fn geodata_ok_problem_names_the_file_skipped_without_core() {
    is(&one(&Mock::healthy(), CheckId::Geodata).await, State::Ok);
    let mut m = Mock::healthy();
    m.geo = (true, false);
    let r = one(&m, CheckId::Geodata).await;
    is(&r, State::Problem);
    assert!(r.detail.contains("geosite.dat") && !r.detail.contains("geoip.dat"));
    m.core = Err("x".into());
    is(&one(&m, CheckId::Geodata).await, State::Skipped);
}

#[tokio::test]
async fn tcp_ok_blocked_timeout_and_no_server() {
    is(&one(&Mock::healthy(), CheckId::ServerTcp).await, State::Ok);
    let mut m = Mock::healthy();
    m.tcp = Err(TcpFail::Blocked);
    let r = one(&m, CheckId::ServerTcp).await;
    is(&r, State::Problem);
    assert_eq!(r.fix, None, "no firewall to set up on Linux");
    let mut w = Mock::windows();
    w.tcp = Err(TcpFail::Blocked);
    assert_eq!(
        one(&w, CheckId::ServerTcp).await.fix,
        Some(Fix::ConfigureFirewall)
    );
    m.tcp = Err(TcpFail::Timeout { secs: 5 });
    is(&one(&m, CheckId::ServerTcp).await, State::Problem);
    m.tcp = Err(TcpFail::Other("network is unreachable".into()));
    is(&one(&m, CheckId::ServerTcp).await, State::Problem);
    m.server = false;
    m.asked.borrow_mut().clear();
    is(&one(&m, CheckId::ServerTcp).await, State::Skipped);
    assert!(
        m.asked.borrow().is_empty(),
        "nothing is asked without a server"
    );
}

#[tokio::test]
async fn url_ping_ok_problem_and_skipped_without_core_or_server() {
    is(&one(&Mock::healthy(), CheckId::ServerUrl).await, State::Ok);
    let mut m = Mock::healthy();
    m.url = Err("timeout".into());
    is(&one(&m, CheckId::ServerUrl).await, State::Problem);
    m.core = Err("x".into());
    is(&one(&m, CheckId::ServerUrl).await, State::Skipped);
    let mut m = Mock::healthy();
    m.server = false;
    is(&one(&m, CheckId::ServerUrl).await, State::Skipped);
}

#[tokio::test]
async fn dns_ok_broken_system_resolver_broken_server_and_not_connected() {
    let r = one(&Mock::healthy(), CheckId::Dns).await;
    is(&r, State::Ok);
    assert!(
        r.detail.contains("2/2") && r.detail.contains("4/4"),
        "{}",
        r.detail
    );
    let mut m = Mock::healthy();
    m.dns_via = None;
    is(&one(&m, CheckId::Dns).await, State::Ok);
    m.dns_direct = false;
    is(&one(&m, CheckId::Dns).await, State::Problem);
    let mut m = Mock::healthy();
    m.dns_via = Some(false);
    is(&one(&m, CheckId::Dns).await, State::Problem);
}

#[tokio::test]
async fn tun_rights_ok_problem_and_skipped_without_core() {
    is(&one(&Mock::healthy(), CheckId::TunRights).await, State::Ok);
    let mut m = Mock::healthy();
    m.tun = vec![Problem::NeedsPrivileges];
    let r = one(&m, CheckId::TunRights).await;
    is(&r, State::Problem);
    assert!(
        !r.detail.contains("second line"),
        "one line only: {}",
        r.detail
    );
    m.tun = vec![Problem::CoreMissing(PathBuf::from("xray"))];
    is(&one(&m, CheckId::TunRights).await, State::Skipped);
    // Not blocking, and not about rights.
    m.tun = vec![Problem::GeodataMissing(PathBuf::from("/x"))];
    is(&one(&m, CheckId::TunRights).await, State::Ok);
}

#[tokio::test]
async fn wintun_ok_problem_and_skipped_on_linux() {
    is(&one(&Mock::windows(), CheckId::Wintun).await, State::Ok);
    let mut w = Mock::windows();
    w.tun = vec![Problem::MissingWintun(PathBuf::from("wintun.dll"))];
    is(&one(&w, CheckId::Wintun).await, State::Problem);
    let mut l = Mock::healthy();
    l.tun = vec![Problem::MissingWintun(PathBuf::from("wintun.dll"))];
    is(&one(&l, CheckId::Wintun).await, State::Skipped);
}

#[tokio::test]
async fn firewall_ok_missing_unreadable_and_skipped() {
    is(&one(&Mock::windows(), CheckId::Firewall).await, State::Ok);
    let mut w = Mock::windows();
    w.firewall = Some(Ok(false));
    let r = one(&w, CheckId::Firewall).await;
    is(&r, State::Problem);
    assert_eq!(r.fix, Some(Fix::ConfigureFirewall));
    w.firewall = Some(Err("com error".into()));
    let r = one(&w, CheckId::Firewall).await;
    is(&r, State::Problem);
    assert_eq!(r.fix, None);
    w.firewall = None;
    is(&one(&w, CheckId::Firewall).await, State::Skipped);
    is(
        &one(&Mock::healthy(), CheckId::Firewall).await,
        State::Skipped,
    );
}

#[tokio::test]
async fn a_leftover_adapter_is_a_problem_with_a_fix_on_windows_only() {
    is(&one(&Mock::windows(), CheckId::Adapter).await, State::Ok);
    let mut w = Mock::windows();
    w.stale = Some("elf-gate".into());
    let r = one(&w, CheckId::Adapter).await;
    is(&r, State::Problem);
    assert_eq!(r.fix, Some(Fix::RemoveAdapter));
    let mut l = Mock::healthy();
    l.stale = Some("elf-gate".into());
    is(&one(&l, CheckId::Adapter).await, State::Skipped);
}

#[tokio::test]
async fn the_system_proxy_ok_leftover_and_unsupported() {
    is(&one(&Mock::healthy(), CheckId::SysProxy).await, State::Ok);
    let mut m = Mock::healthy();
    m.proxy = ProxyView::Ours {
        socks: 10808,
        http: 10809,
    };
    let r = one(&m, CheckId::SysProxy).await;
    is(&r, State::Ok);
    assert!(r.detail.contains("10808") && r.detail.contains("10809"));
    m.running = false;
    let r = one(&m, CheckId::SysProxy).await;
    is(&r, State::Problem);
    assert_eq!(r.fix, Some(Fix::ClearProxy));
    m.proxy = ProxyView::Unsupported;
    is(&one(&m, CheckId::SysProxy).await, State::Skipped);
}

#[tokio::test]
async fn the_vpn_requests_ok_problem_and_skipped_when_not_connected() {
    let r = one(&Mock::healthy(), CheckId::VpnIp).await;
    is(&r, State::Ok);
    assert!(r.detail.contains("203.0.113.7"));
    is(&one(&Mock::healthy(), CheckId::RuDirect).await, State::Ok);

    let mut m = Mock::healthy();
    m.vpn_ip = Err("no answer".into());
    is(&one(&m, CheckId::VpnIp).await, State::Problem);

    // The Russian site sees the server's address: the rule does not work.
    let mut m = Mock::healthy();
    m.ru_ip = Ok("203.0.113.7".into());
    is(&one(&m, CheckId::RuDirect).await, State::Problem);
    m.ru_ip = Err("timeout".into());
    is(&one(&m, CheckId::RuDirect).await, State::Problem);
    let mut m = Mock::healthy();
    m.ru_on = false;
    is(&one(&m, CheckId::RuDirect).await, State::Skipped);

    let mut m = Mock::healthy();
    m.connected = false;
    is(&one(&m, CheckId::VpnIp).await, State::Skipped);
    is(&one(&m, CheckId::RuDirect).await, State::Skipped);
}

// ---------- the report ----------

#[test]
fn the_report_holds_none_of_the_secrets_of_the_config() {
    let secrets = [
        "11111111-1111-1111-1111-111111111111", // uuid
        "vless://11111111-1111-1111-1111-111111111111@vpn.secret-host.example:443?security=reality&pbk=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG&sid=0123abcd#name",
        "https://sub.provider.example/api/v1/token-aaa111",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG", // publicKey
        "0123abcd",                                    // shortId
        "vpn.secret-host.example",
        "203.0.113.7", // an address seen through the VPN
        "198.51.100.9",
    ];
    let results = vec![
        CheckResult::ok(CheckId::VpnIp, "outside address 203.0.113.7".into()),
        CheckResult::problem(
            CheckId::ServerTcp,
            "no answer from vpn.secret-host.example:443".into(),
            "check it".into(),
        ),
        CheckResult::ok(CheckId::RuDirect, "your address 198.51.100.9".into()),
    ];
    let log = vec![
        "12:00:01 info connecting to vpn.secret-host.example".into(),
        "12:00:02 info subscription https://sub.provider.example/api/v1/token-aaa111 updated".into(),
        format!("12:00:03 info link {}", secrets[1]),
        "12:00:04 info id 11111111-1111-1111-1111-111111111111 key AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG sid 0123abcd".into(),
        "12:00:05 info 203.0.113.7 and 198.51.100.9".into(),
    ];
    let text = report(&ReportInput {
        version_line: "elf-gate 1.0.3 (commit abcdef0, release)".into(),
        os: "Linux 7".into(),
        mode: "proxy".into(),
        presets: vec!["ru-direct".into()],
        server_addresses: vec!["vpn.secret-host.example".into(), "203.0.113.7".into()],
        log,
        results: &results,
    });
    for s in secrets {
        assert!(!text.contains(s), "`{s}` is in the report:\n{text}");
    }
    assert!(
        text.contains(&crate::t!("diag.report_server", n = 1)),
        "{text}"
    );
    assert!(text.contains("elf-gate 1.0.3 (commit abcdef0, release)"));
    assert!(text.contains("ru-direct"));
    assert!(text.contains("check it"));
}

#[test]
fn the_report_names_the_servers_in_the_order_of_the_list() {
    let results = vec![CheckResult::ok(
        CheckId::Core,
        "a.example.org b.example.org a.example.org".into(),
    )];
    let text = report(&ReportInput {
        version_line: String::new(),
        os: String::new(),
        mode: String::new(),
        presets: vec![],
        server_addresses: vec!["a.example.org".into(), "b.example.org".into()],
        log: vec![],
        results: &results,
    });
    let one = crate::t!("diag.report_server", n = 1);
    let two = crate::t!("diag.report_server", n = 2);
    assert!(text.contains(&format!("{one} {two} {one}")), "{text}");
}
