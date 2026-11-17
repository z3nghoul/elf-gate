//! The check screen, engine side: the real [`Env`] and the fixes the screen may ask for.

use super::*;
use crate::diag::{Env, Fix, ProxyView, TcpFail};
use crate::net::ping as netping;
use crate::platform::Firewall;
use crate::storage::PingMode;
use crate::sysproxy::ProxyController;
use crate::tun::Problem;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Everything the checks look at, copied out of the engine so the run does not hold it.
pub(super) struct LiveEnv {
    config: Config,
    server: Option<Server>,
    tun_host: Arc<dyn TunHost>,
    proxy: Option<Arc<ProxyController>>,
    firewall: Option<Box<dyn Firewall>>,
    run_dir: PathBuf,
    connected: bool,
    tun_active: bool,
    core_running: bool,
}

fn scrub(text: &str) -> String {
    crate::redact::secrets(text)
}

/// A request through the live local proxy; the answer is the address the far side saw.
async fn address_seen(socks_port: u16, url: &str) -> Result<String, String> {
    let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{socks_port}"))
        .map_err(|e| scrub(&e.to_string()))?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| scrub(&e.to_string()))?;
    let body = client
        .get(url)
        .send()
        .await
        .map_err(|e| scrub(&e.without_url().to_string()))?
        .error_for_status()
        .map_err(|e| scrub(&e.without_url().to_string()))?
        .text()
        .await
        .map_err(|e| scrub(&e.without_url().to_string()))?;
    let ip = body.trim().trim_matches('"').to_string();
    if ip.parse::<std::net::IpAddr>().is_ok() {
        Ok(ip)
    } else {
        Err(crate::t!("diag.not_an_address"))
    }
}

/// Resolves `host` on the far side: a SOCKS5 CONNECT by name, succeeded or not.
async fn socks_resolves(socks_port: u16, host: &str) -> bool {
    let attempt = async {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", socks_port))
            .await
            .ok()?;
        s.write_all(&[5, 1, 0]).await.ok()?;
        let mut method = [0u8; 2];
        s.read_exact(&mut method).await.ok()?;
        if method != [5, 0] {
            return None;
        }
        let name = host.as_bytes();
        let mut req = vec![5, 1, 0, 3, name.len() as u8];
        req.extend_from_slice(name);
        req.extend_from_slice(&443u16.to_be_bytes());
        s.write_all(&req).await.ok()?;
        let mut reply = [0u8; 4];
        s.read_exact(&mut reply).await.ok()?;
        (reply[1] == 0).then_some(())
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(8), attempt).await,
        Ok(Some(()))
    )
}

impl Env for LiveEnv {
    fn windows(&self) -> bool {
        crate::platform::IS_WINDOWS
    }

    fn core_binary(&self) -> Result<PathBuf, String> {
        crate::xray::process::resolve_binary(&self.config.core.xray_path).map_err(|e| e.to_string())
    }

    async fn core_version(&self, core: &Path) -> Result<String, String> {
        crate::xray::checkcache::xray_version(core)
            .await
            .ok_or_else(|| crate::t!("diag.no_version"))
    }

    fn geodata(&self, core: &Path) -> (bool, bool) {
        let dir = crate::xray::process::asset_dir(core);
        (
            dir.join("geoip.dat").is_file(),
            dir.join("geosite.dat").is_file(),
        )
    }

    fn ping_is_url(&self) -> bool {
        self.config.ping.mode == PingMode::Url
    }

    fn has_server(&self) -> bool {
        self.server.is_some()
    }

    async fn tcp(&self) -> Result<u32, TcpFail> {
        let Some(server) = &self.server else {
            return Err(TcpFail::Other(String::new()));
        };
        let limit = Duration::from_millis(self.config.ping.timeout_ms.max(1000));
        let secs = limit.as_secs().max(1);
        if self.tun_active {
            // A plain connect would end in the tunnel: go around it.
            let iface = self.tun_host.physical_interface(&self.config.tun.name);
            return match netping::tcp_ping_via(
                &server.address,
                server.port,
                limit,
                iface.as_deref(),
            )
            .await
            {
                crate::model::server::Ping::Ms(ms) => Ok(ms),
                crate::model::server::Ping::Timeout => Err(TcpFail::Timeout { secs }),
                _ => Err(TcpFail::Other(crate::t!("diag.tcp_unreachable"))),
            };
        }
        let ip = crate::tun::resolve_server(&server.address, server.port)
            .await
            .map_err(|_| TcpFail::Other(crate::t!("diag.tcp_lookup")))?;
        let started = Instant::now();
        match tokio::time::timeout(limit, tokio::net::TcpStream::connect((ip, server.port))).await {
            Ok(Ok(_)) => Ok(started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32),
            Ok(Err(e)) if crate::tun::is_local_block(&e) => Err(TcpFail::Blocked),
            Ok(Err(e)) => Err(TcpFail::Other(scrub(&e.to_string()))),
            Err(_) => Err(TcpFail::Timeout { secs }),
        }
    }

    async fn url_ping(&self) -> Result<u32, String> {
        let server = self.server.as_ref().ok_or_else(String::new)?;
        let binary = self.core_binary()?;
        let limit = Duration::from_millis(self.config.ping.timeout_ms.max(500));
        netping::url_probe(
            &binary,
            &self.config.core,
            server,
            &self.config.ping.url,
            limit,
            &self.run_dir,
        )
        .await
        .map(|d| d.as_millis().min(u128::from(u32::MAX)) as u32)
        .map_err(|e| scrub(&e))
    }

    async fn dns_direct(&self, host: &str) -> bool {
        let lookup = tokio::net::lookup_host((host, 443));
        match tokio::time::timeout(Duration::from_secs(4), lookup).await {
            Ok(Ok(mut found)) => found.next().is_some(),
            _ => false,
        }
    }

    async fn dns_via_server(&self, host: &str) -> Option<bool> {
        if !self.connected {
            return None;
        }
        Some(socks_resolves(self.config.core.socks_port, host).await)
    }

    fn tun_problems(&self) -> Vec<Problem> {
        crate::tun::preflight(self.tun_host.as_ref(), &self.config).problems
    }

    fn explain(&self, problem: &Problem) -> String {
        crate::tun::explain(problem, &self.config)
    }

    fn firewall_rules_in_place(&self) -> Option<Result<bool, String>> {
        let fw = self.firewall.as_ref()?;
        Some(crate::firewall::rules_in_place(
            fw.as_ref(),
            &crate::firewall::programs_for(&self.config),
        ))
    }

    fn stale_adapter(&self) -> Option<String> {
        let name = &self.config.tun.name;
        (self.tun_host.adapter_lifecycle_managed()
            && !self.tun_active
            && self.tun_host.interface_exists(name))
        .then(|| name.clone())
    }

    fn proxy_view(&self) -> ProxyView {
        match &self.proxy {
            Some(c) => c.view(self.config.core.socks_port, self.config.core.http_port),
            None => ProxyView::Unsupported,
        }
    }

    fn core_running(&self) -> bool {
        self.core_running
    }

    fn connected(&self) -> bool {
        self.connected
    }

    fn ru_direct_on(&self) -> bool {
        self.config.presets.enabled.iter().any(|p| p == "ru-direct")
    }

    async fn ip_via_vpn(&self) -> Result<String, String> {
        address_seen(self.config.core.socks_port, "https://api.ipify.org").await
    }

    async fn ip_russian_site(&self) -> Result<String, String> {
        address_seen(
            self.config.core.socks_port,
            "https://ipv4-internet.yandex.net/api/v0/ip",
        )
        .await
    }
}

impl Engine {
    /// The server the checks look at: the one selected in the list, else the connected one.
    fn check_server(&self, selected: Option<u64>) -> Option<Server> {
        let live = match self.conn {
            Conn::Connected(id) | Conn::Connecting(id) => Some(id),
            _ => None,
        };
        selected
            .or(live)
            .and_then(|id| self.server_by_id(id))
            .filter(|s| s.is_supported() && !s.link.is_empty())
            .cloned()
    }

    pub(super) fn run_checks(&mut self, selected: Option<u64>) {
        if self.diag_running {
            return;
        }
        self.diag_running = true;
        let env = LiveEnv {
            config: self.config.clone(),
            server: self.check_server(selected),
            tun_host: self.tun_host.clone(),
            proxy: self.proxy.as_ref().map(|p| p.controller.clone()),
            firewall: crate::platform::firewall(),
            run_dir: self.run_dir.clone(),
            connected: matches!(self.conn, Conn::Connected(_)),
            tun_active: self.tun_active,
            core_running: self.core.is_some(),
        };
        let tx = self.tx.clone();
        self.spawn(async move {
            let sender = tx.clone();
            crate::diag::run(&env, |r| {
                let _ = sender.send(BgEvent::Check(r));
            })
            .await;
            let _ = tx.send(BgEvent::ChecksDone);
        });
    }

    /// What the check screen offered and the user confirmed.
    pub(super) fn apply_fix(&mut self, fix: Fix) {
        let outcome: Result<(), String> = match fix {
            Fix::ClearProxy => {
                match &self.proxy {
                    Some(handle) => handle.send(ProxyCmd::Disable),
                    None => return self.status(crate::t!("diag.fix_failed", error = "-")),
                }
                self.proxy_requested = false;
                Ok(())
            }
            Fix::RemoveAdapter => self
                .tun_host
                .remove_stale_adapter(&self.config.tun.name)
                .map(|_| ()),
            Fix::ConfigureFirewall => {
                self.firewall_setup_requested = true;
                Ok(())
            }
            Fix::PingToTcp => {
                self.apply_setting(crate::proto::Setting::PingMode(PingMode::Tcp));
                Ok(())
            }
        };
        self.log(Level::Info, format!("check screen: {fix:?}: {outcome:?}"));
        match outcome {
            Ok(()) => self.status(crate::t!("diag.fix_done")),
            Err(e) => self.status(crate::t!("diag.fix_failed", error = scrub(&e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::mock::{MockFirewall, MockProxy, MockTunHost, SharedMock};
    use crate::platform::{FwAction, FwDirection, FwRule};
    use crate::test_support::TempDir;
    use tokio::sync::mpsc::unbounded_channel;

    fn env(tun: MockTunHost, proxy: Option<Arc<ProxyController>>, dir: &Path) -> LiveEnv {
        LiveEnv {
            config: crate::test_support::config_ru(),
            server: None,
            tun_host: Arc::new(tun),
            proxy,
            firewall: None,
            run_dir: dir.to_path_buf(),
            connected: false,
            tun_active: false,
            core_running: false,
        }
    }

    fn controller(user: &[(&str, &str)], dir: &Path) -> Arc<ProxyController> {
        Arc::new(ProxyController::new(
            Box::new(SharedMock(Arc::new(MockProxy::with_user_settings(user)))),
            StateStore::new(dir),
        ))
    }

    #[test]
    fn the_proxy_view_tells_our_ports_from_the_users_own_settings() {
        let dir = TempDir::new("diag-proxy");
        let ours = controller(
            &[("server", "127.0.0.1:10809"), ("enabled", "1")],
            dir.path(),
        );
        let theirs = controller(
            &[("server", "proxy.corp.example:3128"), ("enabled", "1")],
            dir.path(),
        );
        let off = controller(&[("enabled", "0")], dir.path());
        let view = |c| env(MockTunHost::healthy(), Some(c), dir.path()).proxy_view();
        assert_eq!(
            view(ours),
            ProxyView::Ours {
                socks: 10808,
                http: 10809
            }
        );
        assert_eq!(view(theirs), ProxyView::NotOurs);
        assert_eq!(view(off), ProxyView::NotOurs);
        assert_eq!(
            env(MockTunHost::healthy(), None, dir.path()).proxy_view(),
            ProxyView::Unsupported
        );
    }

    #[test]
    fn a_leftover_adapter_is_seen_only_where_adapters_stay_and_no_tun_core_runs() {
        let dir = TempDir::new("diag-adapter");
        let mut host = MockTunHost::healthy();
        host.managed_adapter = true;
        host.iface_present = true;
        let mut e = env(host, None, dir.path());
        assert_eq!(e.stale_adapter(), Some(e.config.tun.name.clone()));
        e.tun_active = true;
        assert_eq!(
            e.stale_adapter(),
            None,
            "our own live adapter is not a leftover"
        );
        let mut linux = MockTunHost::healthy();
        linux.iface_present = true;
        assert_eq!(env(linux, None, dir.path()).stale_adapter(), None);
    }

    #[test]
    fn firewall_rules_are_in_place_only_when_every_program_has_both_directions() {
        let programs = vec![PathBuf::from(r"C:\elf\elf-gate.exe")];
        let rule = |d| FwRule {
            name: crate::firewall::RULE_NAME.into(),
            program: r"c:/elf/ELF-GATE.exe".into(),
            direction: d,
            action: FwAction::Allow,
            enabled: true,
        };
        let both = MockFirewall::with_rules(vec![rule(FwDirection::In), rule(FwDirection::Out)]);
        assert_eq!(crate::firewall::rules_in_place(&both, &programs), Ok(true));
        let one = MockFirewall::with_rules(vec![rule(FwDirection::In)]);
        assert_eq!(crate::firewall::rules_in_place(&one, &programs), Ok(false));
        let mut blocked = rule(FwDirection::Out);
        blocked.action = FwAction::Block;
        let block = MockFirewall::with_rules(vec![rule(FwDirection::In), blocked]);
        assert_eq!(
            crate::firewall::rules_in_place(&block, &programs),
            Ok(false)
        );
    }

    fn engine(dir: &Path) -> Engine {
        let (tx, _rx) = unbounded_channel();
        Engine::build(
            tx,
            crate::test_support::config_ru(),
            Some(Storage::new(dir)),
            false,
        )
    }

    #[tokio::test]
    async fn fixes_do_what_they_say_and_nothing_else() {
        let dir = TempDir::new("diag-fix");
        let mut e = engine(dir.path());
        e.apply_fix(Fix::PingToTcp);
        assert_eq!(e.config.ping.mode, PingMode::Tcp);
        assert!(!e.firewall_setup_requested);
        e.apply_fix(Fix::ConfigureFirewall);
        assert!(e.firewall_setup_requested);
    }

    #[tokio::test]
    async fn removing_a_leftover_adapter_names_only_ours() {
        let dir = TempDir::new("diag-adapter-fix");
        let mut host = MockTunHost::healthy();
        host.managed_adapter = true;
        let host = Arc::new(host);
        let mut e = engine(dir.path()).with_tun_host(host.clone());
        e.apply_fix(Fix::RemoveAdapter);
        assert_eq!(
            *host.removed_names.lock().unwrap(),
            vec![e.config.tun.name.clone()]
        );
    }

    #[tokio::test]
    async fn a_second_run_does_not_start_while_one_is_in_flight() {
        let dir = TempDir::new("diag-busy");
        let mut e = engine(dir.path());
        e.diag_running = true;
        e.run_checks(None);
        assert!(e.diag_running);
        e.on_bg(BgEvent::ChecksDone);
        assert!(!e.diag_running);
    }
}
