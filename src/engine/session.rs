//! Connecting, TUN mode, the connection check, first-run questions, privileges.

use super::*;
use crate::net::health;
use crate::storage::{CoreConfig, PresetsConfig};
use crate::tun::{self, Problem};
use crate::xray::config::{build_with, Failover};
use crate::xray::geodata::{drop_missing, Geo};
use crate::xray::process::{resolve_binary, StartOptions};
use std::path::Path;

/// Why a start failed, in words for the user.
struct Failure {
    message: String,
    needs_privileges: bool,
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Failure {
            message,
            needs_privileges: false,
        }
    }
}

fn log_warning(tx: &BgTx, text: String) {
    let _ = tx.send(BgEvent::Log(LogLine {
        time: now_hms(),
        level: Level::Warning,
        text,
    }));
}

/// Everything that happens between "connect" and "the core is listening", off the UI thread.
#[allow(clippy::too_many_arguments)]
async fn start_core(
    server: &Server,
    mode: Mode,
    setup: Option<tun::Setup>,
    core_cfg: &CoreConfig,
    config: &Config,
    host: &dyn TunHost,
    run_dir: &Path,
    tx: &BgTx,
    store: Option<&StateStore>,
    checker: &Checker,
    backup: Option<Server>,
    known_hosts: Vec<String>,
) -> Result<Core, Failure> {
    // The server must answer over TCP before anything else: afterwards, with the tunnel up,
    // this machine's own connections would go through the tunnel. The address is resolved
    // here too, so Xray never has to resolve it through the tunnel.
    let ip = tun::resolve_server(&server.address, server.port).await?;
    tun::tcp_reachable(ip, server.port, Duration::from_secs(4))
        .await
        .map_err(|e| crate::t!("eng.server_tcp_down", error = e))?;

    // Ask Xray about the server itself first: a refusal greys the server out.
    if let Verdict::Rejected(reason) = checker.check(core_cfg, server, run_dir).await {
        let _ = tx.send(BgEvent::ServerRejected {
            id: server.id,
            reason: reason.clone(),
        });
        return Err(crate::t!("eng.server_rejected", reason = reason).into());
    }

    let binary = match &setup {
        Some(s) => s.core.clone(),
        None => resolve_binary(&core_cfg.xray_path).map_err(|e| e.to_string())?,
    };
    let mut plan = tun::build_plan(config, host, mode, (mode == Mode::Tun).then_some(ip));
    if mode == Mode::Tun {
        // Every server and subscription host stays outside the tunnel: pings, the connection
        // itself, downloads. Resolved now, while the names still resolve normally.
        let mut ips: Vec<String> = tun::resolve_all(&known_hosts)
            .await
            .iter()
            .map(|ip| ip.to_string())
            .collect();
        if !ips.contains(&ip.to_string()) {
            ips.push(ip.to_string());
        }
        if server.full.is_some() {
            plan.pin = tun::resolve_map(&server.all_hosts()).await;
            for ip in plan.pin.values() {
                if !ips.contains(ip) {
                    ips.push(ip.clone());
                }
            }
        }
        plan.direct_ips = ips;
        plan.direct_domains = known_hosts
            .iter()
            .filter(|h| h.parse::<std::net::IpAddr>().is_err())
            .map(|h| format!("full:{h}"))
            .collect();
    }
    if let Some(backup) = backup {
        // In TUN mode the backup's address must be resolved now too (never through the tunnel).
        let backup_ip = if mode == Mode::Tun {
            match tun::resolve_server(&backup.address, backup.port).await {
                Ok(ip) => Some(ip.to_string()),
                Err(e) => {
                    log_warning(
                        tx,
                        crate::t!("eng.backup_skipped", name = backup.name, error = e),
                    );
                    None
                }
            }
        } else {
            Some(String::new())
        };
        if let Some(ip) = backup_ip {
            plan.failover = Some(Failover::new(
                backup,
                (!ip.is_empty()).then_some(ip),
                config.ping.url.clone(),
            ));
        }
    }
    if let Some(geo) = binary.parent().and_then(Geo::load) {
        for warning in drop_missing(&mut plan.rules, &geo) {
            let _ = tx.send(BgEvent::Log(LogLine {
                time: now_hms(),
                level: Level::Warning,
                text: warning,
            }));
        }
    }
    let cfg = build_with(server, core_cfg, &plan).map_err(|e| e.to_string())?;
    if let Verdict::Rejected(reason) = checker.check_config(&binary, &cfg, run_dir).await {
        return Err(crate::t!(
            "eng.final_rejected",
            reason = reason,
            core = crate::xray::process::describe_core(&binary)
        )
        .into());
    }

    let opts = StartOptions {
        binary: setup.as_ref().map(|s| s.core.clone()),
        supervised: setup.as_ref().is_some_and(|s| s.supervised),
        interface: setup.as_ref().map(|s| s.interface.clone()),
        config_name: None,
    };
    let core = Core::start_with(core_cfg, &cfg, run_dir, tx.clone(), &opts)
        .await
        .map_err(|e| {
            let text = e.to_string();
            Failure {
                needs_privileges: mode == Mode::Tun && tun::looks_like_missing_privileges(&text),
                message: text,
            }
        })?;
    if let (Some(store), Some(setup)) = (store, &setup) {
        if let Some(pid) = core.pid() {
            tun::mark_up(store, pid, &setup.interface);
        }
    }
    Ok(core)
}

impl Engine {
    pub(super) fn connect(&mut self, id: u64) {
        if self.busy {
            self.status(crate::t!("eng.wait_core"));
            return;
        }
        let Some(server) = self.server_by_id(id).cloned() else {
            return;
        };

        if server.link.is_empty() {
            self.connect_mock(id, &server);
            return;
        }

        let mode = self.mode;
        let mut setup = None;
        if mode == Mode::Tun {
            if self.tun_first_run() {
                self.alert(Alert::Ask {
                    text: crate::t!("eng.tun_intro"),
                    ask: Ask::PresetOffer(id),
                });
                return;
            }
            let preflight = tun::preflight(&*self.tun_host, &self.config);
            if let Some(problem) = preflight.blocking().first() {
                self.remember_server(id);
                self.show_problem(problem);
                return;
            }
            if !self.caps_warned {
                let rules = crate::model::rule::effective_rules(
                    self.config.mode.routing,
                    &self.config.rules,
                    &self.config.presets.enabled,
                    &crate::model::rule::builtin_presets(),
                    cfg!(windows),
                );
                let core = preflight.setup.as_ref().map(|s| s.core.clone());
                let caps = core.and_then(|c| self.tun_host.core_capabilities(&c));
                if let Some(text) =
                    tun::process_caps_warning(caps.as_deref(), !rules.processes.is_empty())
                {
                    self.caps_warned = true;
                    self.logt(Level::Warning, || crate::t!("eng.tun_caps_log"));
                    self.alert(Alert::Notice(text));
                }
            }
            // Warnings (for example a strict rp_filter) do not stop the start.
            if let Some(warning) = preflight.problems.first() {
                self.show_problem(warning);
            }
            setup = preflight.setup;
        }

        self.traffic = Traffic::default();
        self.process_unresolved = 0;
        self.health = HealthState::Unknown;
        self.conn = Conn::Connecting(id);
        self.conn_mode = mode;
        let old = self.core.take();
        self.log(
            Level::Info,
            format!("starting core for {} ({})", server.name, mode_name(mode)),
        );
        self.busy = true;

        let tx = self.tx.clone();
        let core_cfg = self.config.core.clone();
        let config = self.config.clone();
        let host = self.tun_host.clone();
        let store = self.state_store.clone();
        let run_dir = self.run_dir.clone();
        let checker = self.checker.clone();
        let backup = self.backup_for(id);
        let known_hosts = self.known_hosts();
        if let Some(b) = &backup {
            self.logt(Level::Info, || crate::t!("eng.backup_log", name = b.name));
        }
        tokio::spawn(async move {
            if let Some(old) = old {
                old.stop().await;
                if let Some(store) = &store {
                    tun::mark_down(store);
                }
            }
            let result = start_core(
                &server,
                mode,
                setup,
                &core_cfg,
                &config,
                host.as_ref(),
                &run_dir,
                &tx,
                store.as_ref(),
                &checker,
                backup,
                known_hosts,
            )
            .await;
            checker.flush();
            let ev = match result {
                Ok(core) => BgEvent::CoreStarted {
                    id,
                    core: Box::new(core),
                },
                Err(f) => BgEvent::CoreFailed {
                    id,
                    error: f.message,
                    needs_privileges: f.needs_privileges,
                },
            };
            let _ = tx.send(ev);
        });
    }

    /// Addresses that must stay outside the tunnel: every server's host and the hosts of the
    /// subscription URLs.
    fn known_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = Vec::new();
        let mut add = |h: String| {
            if !h.is_empty() && !hosts.contains(&h) {
                hosts.push(h);
            }
        };
        for s in self.subs.iter().flat_map(|g| g.servers.iter()) {
            for h in s.all_hosts() {
                add(h);
            }
        }
        for sc in &self.config.subscriptions {
            if let Some(h) = url::Url::parse(&sc.url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_string))
            {
                add(h);
            }
        }
        hosts
    }

    /// Demo servers (debug builds): no real process.
    fn connect_mock(&mut self, id: u64, server: &Server) {
        self.traffic = Traffic::default();
        self.conn = Conn::Connecting(id);
        let old = self.core.take();
        self.log(Level::Info, format!("connecting to {} (mock)", server.name));
        if let Some(old) = old {
            self.spawn_stop(old);
        }
        // Mock rule: servers whose last ping failed refuse the connection.
        let ok = !matches!(server.ping, Ping::Timeout | Ping::Error);
        mock::spawn_connect(self.tx.clone(), id, ok);
    }

    /// Stops a core in the background; `busy` stays set until it is done.
    pub(super) fn spawn_stop(&mut self, core: Core) {
        self.busy = true;
        let tx = self.tx.clone();
        let store = self.state_store.clone();
        tokio::spawn(async move {
            core.stop().await;
            if let Some(store) = &store {
                tun::mark_down(store);
            }
            let _ = tx.send(BgEvent::CoreStopped);
        });
    }

    pub(super) fn on_core_started(&mut self, id: u64, core: Core) {
        let pid = core.pid().map(|p| p.to_string()).unwrap_or_default();
        self.core = Some(core);
        self.conn = Conn::Connected(id);
        self.tun_active = self.conn_mode == Mode::Tun;
        self.request_proxy_on();
        let name = self.server_by_id(id).map(|s| s.name.clone());
        self.log(
            Level::Info,
            format!(
                "connected to {} ({}, xray pid {pid})",
                name.unwrap_or_default(),
                mode_name(self.conn_mode)
            ),
        );
        self.remember_server(id);
        self.start_stats();
        self.spawn_health(id);
    }

    pub(super) fn on_core_failed(&mut self, id: u64, error: String, needs_privileges: bool) {
        self.log(Level::Error, format!("[Error] {error}"));
        if self.conn != Conn::Connecting(id) {
            return;
        }
        self.tun_active = false;
        self.conn = Conn::Error(crate::t!("eng.core_start_failed"));
        self.request_proxy_off();
        if needs_privileges {
            self.show_problem(&Problem::NeedsPrivileges);
        } else {
            self.error_alert(error);
        }
    }

    // ---------- the connection check ----------

    fn spawn_health(&mut self, id: u64) {
        self.health = HealthState::Checking;
        let tx = self.tx.clone();
        let socks_port = self.config.core.socks_port;
        tokio::spawn(async move {
            // The first request right after the start can race with the routes settling.
            let mut last = String::new();
            for attempt in 0..2 {
                match health::check(socks_port, health::HEALTH_TIMEOUT).await {
                    Ok(latency) => {
                        let _ = tx.send(BgEvent::Health {
                            id,
                            result: Ok(latency),
                        });
                        return;
                    }
                    Err(e) => last = e,
                }
                if attempt == 0 {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
            let _ = tx.send(BgEvent::Health {
                id,
                result: Err(last),
            });
        });
    }

    pub(super) fn on_health(&mut self, id: u64, result: Result<Duration, String>) {
        if self.conn != Conn::Connected(id) {
            return;
        }
        match result {
            Ok(latency) => {
                self.log(
                    Level::Info,
                    format!("connection check passed ({} ms)", latency.as_millis()),
                );
                self.health = HealthState::Ok(latency);
            }
            Err(e) => {
                self.log(
                    Level::Warning,
                    format!("[Warning] connection check failed: {e}"),
                );
                self.health = HealthState::Failed(e);
                // The server answers over TCP but nothing passes: another fingerprint may help.
                // (Not in TUN mode: a temporary core's own traffic would enter the tunnel.)
                if self.conn_mode == Mode::Proxy {
                    self.on_fp_suspect(id);
                }
            }
        }
    }

    // ---------- problems, questions, privileges ----------

    /// Shows what is wrong with TUN and how to fix it. Blocking problems are errors,
    /// the rest are notices. Windows offers to restart with administrator rights.
    pub(super) fn show_problem(&mut self, problem: &Problem) {
        let text = tun::explain(problem, &self.config);
        self.log(
            Level::Warning,
            format!("TUN: {}", text.lines().next().unwrap_or_default()),
        );
        self.alert(match problem {
            Problem::NeedsPrivileges if cfg!(windows) => Alert::Ask {
                text,
                ask: Ask::RelaunchElevated,
            },
            p if p.is_blocking() => Alert::Error(text),
            _ => Alert::Notice(text),
        });
    }

    /// `"<group>/<name>"` of a server, as stored in `[ui].last_server`.
    fn server_key(&self, id: u64) -> Option<String> {
        self.subs.iter().find_map(|sub| {
            sub.servers
                .iter()
                .find(|s| s.id == id)
                .map(|s| format!("{}/{}", sub.name, s.name))
        })
    }

    fn remember_server(&mut self, id: u64) {
        if let Some(key) = self.server_key(id) {
            if self.config.ui.last_server.as_deref() != Some(&key) {
                self.config.ui.last_server = Some(key);
                self.save_config();
            }
        }
    }

    /// The very first TUN start with nothing configured yet.
    pub(super) fn tun_first_run(&self) -> bool {
        !self.config.ui.tun_intro_done
            && self.config.rules.is_empty()
            && self.config.presets.enabled == PresetsConfig::default().enabled
    }

    pub(super) fn accept_discord_preset(&mut self) {
        self.config.mode.routing = crate::model::rule::RoutingMode::Include;
        if !self
            .config
            .presets
            .enabled
            .iter()
            .any(|p| p == "discord-only")
        {
            self.config.presets.enabled.push("discord-only".into());
        }
        self.config.ui.tun_intro_done = true;
        self.save_config();
        self.log(
            Level::Info,
            "preset discord-only enabled (routing: include)",
        );
    }

    /// Windows: the process stops cleanly and starts again with administrator rights, straight
    /// into TUN. (It must release the single-instance lock first, so the loop does the actual
    /// launch after the shutdown.)
    pub(super) fn restart_elevated(&mut self) {
        self.relaunch_elevated = true;
        self.should_exit = true;
    }

    // ---------- startup ----------

    /// Stops a core a crashed run left behind. Returns a note for the log.
    pub fn startup_tun_cleanup(&mut self) -> Option<String> {
        let store = self.state_store.clone()?;
        let note = tun::cleanup_stale(&*self.tun_host, &store)?;
        self.log(Level::Warning, format!("TUN: {note}"));
        Some(note)
    }

    /// `--tun`: switch to TUN and connect to the server used last.
    pub fn start_tun_from_cli(&mut self) {
        if !crate::build_info::TUN_AVAILABLE {
            self.status(crate::t!("eng.tun_unavailable"));
            return;
        }
        self.mode = Mode::Tun;
        self.config.mode.traffic = Mode::Tun;
        self.connect_last_server();
    }

    /// `[ui].auto_connect`: connect to the last server in the last traffic mode.
    pub fn auto_connect(&mut self) {
        if !self.config.ui.auto_connect {
            return;
        }
        self.mode = self.config.mode.traffic;
        self.logt(Level::Info, || crate::t!("eng.auto_connect_log"));
        self.connect_last_server();
    }

    fn connect_last_server(&mut self) {
        let wanted = self.config.ui.last_server.clone();
        let found = self.subs.iter().find_map(|sub| {
            sub.servers
                .iter()
                .find(|s| wanted.as_deref() == Some(&format!("{}/{}", sub.name, s.name)))
                .filter(|s| s.is_supported())
                .map(|s| s.id)
        });
        match found {
            Some(id) => self.connect(id),
            None => self.status(crate::t!("eng.no_auto_server")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::rule::RoutingMode;
    use crate::platform::mock::MockTunHost;
    use tokio::sync::mpsc::unbounded_channel;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("elf-gate-session-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// An app in TUN mode with one real server and a scripted host. The TUN core path points at
    /// a file that exists unless `core_exists` is false.
    fn tun_app(host: MockTunHost, core_exists: bool, dir: &Path) -> (Engine, u64) {
        let mut config = Config::default();
        config.tun.xray_path = if core_exists {
            let core = dir.join("xray");
            std::fs::write(&core, b"x").unwrap();
            std::fs::write(dir.join("geoip.dat"), b"x").unwrap();
            std::fs::write(dir.join("geosite.dat"), b"x").unwrap();
            core.display().to_string()
        } else {
            "/definitely/not/here/xray".into()
        };
        let (tx, _rx) = unbounded_channel();
        let mut a = Engine::build(tx, config, None, false).with_tun_host(Arc::new(host));
        a.add_link("vless://u@10.0.0.5:443?security=none#Real".into());
        a.mode = Mode::Tun;
        let id = a.subs.last().unwrap().servers[0].id;
        (a, id)
    }

    #[tokio::test]
    async fn first_tun_start_offers_the_discord_preset() {
        let dir = temp_dir("offer");
        let (mut a, id) = tun_app(MockTunHost::healthy(), true, &dir);
        a.connect(id);
        let alerts = a.alerts();
        let Some(Alert::Ask { text, ask }) = alerts.first() else {
            panic!("preset offer expected, got {alerts:?}")
        };
        assert_eq!(*ask, Ask::PresetOffer(id));
        assert!(text.contains("Discord"), "{text}");
        assert_eq!(
            a.conn,
            Conn::Disconnected,
            "nothing starts before the answer"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn accepting_the_offer_switches_to_include_with_discord_only() {
        let dir = temp_dir("accept");
        // The core is missing, so after the offer the start stops at the problem popup
        // instead of spawning anything.
        let (mut a, id) = tun_app(MockTunHost::healthy(), false, &dir);
        assert_eq!(a.config.mode.routing, RoutingMode::Exclude);
        a.handle_cmd(Cmd::Answer {
            ask: Ask::PresetOffer(id),
            yes: true,
        });
        assert_eq!(a.config.mode.routing, RoutingMode::Include);
        assert!(a
            .config
            .presets
            .enabled
            .contains(&"discord-only".to_string()));
        assert!(a
            .config
            .presets
            .enabled
            .contains(&"local-direct".to_string()));
        assert!(a.config.ui.tun_intro_done);
        assert!(
            matches!(a.alerts().last(), Some(Alert::Error(_))),
            "the missing core is reported: {:?}",
            a.alerts()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn declining_the_offer_keeps_everything_through_the_vpn() {
        let dir = temp_dir("decline");
        let (mut a, id) = tun_app(MockTunHost::healthy(), false, &dir);
        a.handle_cmd(Cmd::Answer {
            ask: Ask::PresetOffer(id),
            yes: false,
        });
        assert_eq!(a.config.mode.routing, RoutingMode::Exclude);
        assert_eq!(a.config.presets.enabled, ["local-direct"]);
        assert!(
            a.config.ui.tun_intro_done,
            "the question is asked only once"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn the_offer_is_not_repeated_once_answered_or_once_rules_exist() {
        let dir = temp_dir("once");
        let (mut a, _) = tun_app(MockTunHost::healthy(), true, &dir);
        assert!(a.tun_first_run());
        a.config.ui.tun_intro_done = true;
        assert!(!a.tun_first_run());
        a.config.ui.tun_intro_done = false;
        a.config.rules.push(Rule::new(RuleKind::Process, "obs"));
        assert!(
            !a.tun_first_run(),
            "a user who made rules does not need the question"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn blocking_problems_stop_the_start_with_instructions() {
        let dir = temp_dir("blocking");
        let cases: Vec<(MockTunHost, bool, &str)> = vec![
            (
                MockTunHost::healthy(),
                false,
                if cfg!(windows) {
                    "xray.exe"
                } else {
                    "sudo setcap cap_net_admin,cap_sys_ptrace,cap_dac_read_search+ep"
                },
            ),
            (
                MockTunHost {
                    tun_device: false,
                    ..MockTunHost::healthy()
                },
                true,
                "/dev/net/tun",
            ),
            (
                MockTunHost {
                    wintun_missing: true,
                    ..MockTunHost::healthy()
                },
                true,
                "wintun.dll",
            ),
            (
                MockTunHost {
                    untrusted: Some("принадлежит не root (uid 1000)".into()),
                    ..MockTunHost::healthy()
                },
                true,
                "не root",
            ),
        ];
        for (host, core_exists, needle) in cases {
            let (mut a, id) = tun_app(host, core_exists, &dir);
            a.config.ui.tun_intro_done = true;
            a.connect(id);
            let text = match a.alerts().last() {
                Some(Alert::Error(t)) => t.clone(),
                other => panic!("an error alert expected for {needle}, got {other:?}"),
            };
            assert!(text.contains(needle), "{needle} not in: {text}");
            assert_eq!(a.conn, Conn::Disconnected);
            assert!(!a.busy, "nothing was spawned");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn missing_privileges_get_the_right_dialog_for_the_platform() {
        let dir = temp_dir("privileges");
        let host = MockTunHost {
            can_create_tun: Some(false),
            ..MockTunHost::healthy()
        };
        let (mut a, id) = tun_app(host, true, &dir);
        a.config.ui.tun_intro_done = true;
        a.connect(id);
        if cfg!(windows) {
            assert!(matches!(
                a.alerts().last(),
                Some(Alert::Ask {
                    ask: Ask::RelaunchElevated,
                    ..
                })
            ));
        } else {
            let Some(Alert::Error(text)) = a.alerts().last().cloned() else {
                panic!("{:?}", a.alerts())
            };
            assert!(
                text.contains("sudo setcap") && text.contains("sudo elf-gate"),
                "{text}"
            );
        }
        // The server is remembered so an elevated restart can reconnect to it.
        assert_eq!(a.config.ui.last_server.as_deref(), Some("manual/Real"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn declining_elevation_explains_that_tun_needs_it() {
        let (tx, _rx) = unbounded_channel();
        let mut a = Engine::build(tx, Config::default(), None, false);
        a.handle_cmd(Cmd::Answer {
            ask: Ask::RelaunchElevated,
            yes: false,
        });
        assert!(a.last_status().unwrap().contains("администратора"));
    }

    #[tokio::test]
    async fn a_start_error_about_permissions_becomes_the_privileges_dialog() {
        let (tx, _rx) = unbounded_channel();
        let mut a = Engine::build(tx, Config::default(), None, false);
        a.add_link("vless://u@10.0.0.5:443?security=none#Real".into());
        let id = a.subs[0].servers[0].id;
        a.conn = Conn::Connecting(id);
        a.on_core_failed(
            id,
            "ядро завершилось сразу (operation not permitted)".into(),
            true,
        );
        assert!(matches!(a.conn, Conn::Error(_)));
        assert!(!a.alerts().is_empty());
        // An ordinary failure shows the error text itself.
        a.conn = Conn::Connecting(id);
        a.on_core_failed(
            id,
            "порт 10808 (socks) уже занят другой программой".into(),
            false,
        );
        assert!(matches!(a.alerts().last(), Some(Alert::Error(t)) if t.contains("10808")));
    }

    #[tokio::test]
    async fn strict_rp_filter_is_a_notice_and_does_not_stop_the_start() {
        let dir = temp_dir("rp");
        let host = MockTunHost {
            rp: Some(crate::platform::RpFilter {
                interface: "wlan0".into(),
                value: 1,
            }),
            ..MockTunHost::healthy()
        };
        let (mut a, id) = tun_app(host, true, &dir);
        a.config.ui.tun_intro_done = true;
        a.connect(id);
        // A notice, and the start went on (the background task was spawned).
        assert!(
            matches!(a.alerts().last(), Some(Alert::Notice(t)) if t.contains("sysctl -w") && t.contains("не меняет"))
        );
        assert_eq!(a.conn, Conn::Connecting(id));
        assert!(a.busy);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn connection_check_results_are_stored_and_late_ones_ignored() {
        let (tx, _rx) = unbounded_channel();
        let mut a = Engine::build(tx, Config::default(), None, false);
        a.add_link("vless://u@h.example.com:443?security=none#R".into());
        let id = a.subs[0].servers[0].id;
        a.conn = Conn::Connected(id);
        a.on_health(id, Ok(Duration::from_millis(80)));
        assert_eq!(a.health, HealthState::Ok(Duration::from_millis(80)));
        a.on_health(id, Err("нет ответа за 8 с".into()));
        assert!(matches!(a.health, HealthState::Failed(_)));
        a.conn = Conn::Disconnected;
        a.health = HealthState::Unknown;
        a.on_health(id, Err("late".into()));
        assert_eq!(a.health, HealthState::Unknown);
    }

    #[tokio::test]
    async fn tun_toggle_switches_mode_and_remembers_it() {
        let dir = temp_dir("toggle");
        let storage = Storage::new(&dir);
        let (tx, _rx) = unbounded_channel();
        let mut a = Engine::build(tx, Config::default(), Some(storage.clone()), false);
        assert_eq!(a.mode, Mode::Proxy);
        a.handle_cmd(Cmd::ToggleMode);
        assert_eq!(a.mode, Mode::Tun);
        assert_eq!(storage.load().unwrap().mode.traffic, Mode::Tun);
        a.handle_cmd(Cmd::ToggleMode);
        assert_eq!(a.mode, Mode::Proxy);
        assert_eq!(storage.load().unwrap().mode.traffic, Mode::Proxy);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn cli_tun_connects_to_the_last_server_or_explains() {
        let dir = temp_dir("cli");
        let (mut a, _) = tun_app(MockTunHost::healthy(), false, &dir);
        a.mode = Mode::Proxy;
        a.config.ui.last_server = None;
        a.start_tun_from_cli();
        assert!(a.last_status().unwrap().contains("Нет сервера"));

        a.config.ui.last_server = Some("manual/Real".into());
        a.config.ui.tun_intro_done = true;
        a.start_tun_from_cli();
        assert_eq!(a.mode, Mode::Tun);
        // The core is missing in this fixture: the start stops at the problem popup.
        assert!(matches!(a.alerts().last(), Some(Alert::Error(_))));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn auto_connect_is_off_by_default_and_uses_the_last_mode_when_on() {
        let dir = temp_dir("auto");
        let (mut a, id) = tun_app(MockTunHost::healthy(), false, &dir);
        a.mode = Mode::Proxy;
        a.config.mode.traffic = Mode::Tun;
        a.config.ui.last_server = Some("manual/Real".into());
        a.config.ui.tun_intro_done = true;

        a.auto_connect();
        assert_eq!(
            a.conn,
            Conn::Disconnected,
            "off by default: nothing happens"
        );
        assert!(a.alerts().is_empty());

        a.config.ui.auto_connect = true;
        a.auto_connect();
        assert_eq!(a.mode, Mode::Tun, "the last traffic mode is restored");
        // The TUN core is missing in this fixture, so the start stops at the problem popup:
        // proof that the connection was attempted for the remembered server.
        assert!(matches!(a.alerts().last(), Some(Alert::Error(_))));
        assert_eq!(a.server_by_id(id).unwrap().name, "Real");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn startup_cleans_up_a_core_left_by_a_crash() {
        let dir = temp_dir("cleanup");
        let store = StateStore::new(&dir);
        tun::mark_up(&store, 777, "elfgate0");
        let host = Arc::new(MockTunHost::healthy());
        let (tx, _rx) = unbounded_channel();
        let mut a = Engine::build(tx, Config::default(), None, false)
            .with_state_store(store.clone())
            .with_tun_host(host.clone());
        let note = a.startup_tun_cleanup().unwrap();
        assert!(note.contains("остановлен"), "{note}");
        assert_eq!(host.killed.lock().unwrap().as_slice(), &[777]);
        assert!(store.load().unwrap().tun.is_none());
        assert!(a.logged("TUN:"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_missing_capability_with_process_rules_warns_once_and_does_not_stop_the_start() {
        let dir = temp_dir("caps");
        let host = MockTunHost {
            caps: Some("/x/xray cap_net_admin=ep".into()),
            ..MockTunHost::healthy()
        };
        let (mut a, id) = tun_app(host, true, &dir);
        a.config.ui.tun_intro_done = true;
        a.config.rules.push(Rule::new(RuleKind::Process, "Discord"));
        a.connect(id);
        let notes: Vec<_> = a
            .alerts()
            .into_iter()
            .filter(|x| matches!(x, Alert::Notice(t) if t.contains("cap_sys_ptrace")))
            .collect();
        assert_eq!(notes.len(), 1);
        assert_eq!(a.conn, Conn::Connecting(id), "the start went on");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn process_detection_noise_never_reaches_the_screen_and_is_counted_unless_verbose() {
        let noise = |n: u32| {
            BgEvent::Log(LogLine {
                time: "t".into(),
                level: Level::Error,
                text: format!("[xray:err] [Error] app/router: Unables to find local process name: common/net: no process found for inode {n}"),
            })
        };
        let other = BgEvent::Log(LogLine {
            time: "t".into(),
            level: Level::Warning,
            text: "[xray:err] [Warning] connection for 203.0.113.9:443 not found in /proc/net/tcp"
                .into(),
        });
        let (tx, _rx) = unbounded_channel();
        let mut a = Engine::build(tx, Config::default(), None, false);
        for n in 0..300 {
            a.on_bg(noise(n));
        }
        a.on_bg(other);
        assert!(!a.logged("no process found") && !a.logged("not found in /proc/net"));
        assert_eq!(a.process_unresolved, 301, "counted, not shown");
        assert_eq!(
            a.view().process_unresolved,
            301,
            "the details show the count"
        );

        // The detailed core log brings the lines back as they are.
        a.config.core.verbose_log = true;
        a.on_bg(noise(1));
        assert!(a.logged("no process found"));
    }
}
