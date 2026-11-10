//! Connecting, TUN mode, the connection check, first-run questions, privileges.

use super::*;
use crate::net::health;
use crate::platform;
use crate::storage::{CoreConfig, PresetsConfig};
use crate::tun::{self, Problem};
use crate::xray::config::build_with;
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
) -> Result<Core, Failure> {
    // The server must answer over TCP before anything else: afterwards, with the tunnel up,
    // this machine's own connections would go through the tunnel. The address is resolved
    // here too, so Xray never has to resolve it through the tunnel.
    let ip = tun::resolve_server(&server.address, server.port).await?;
    tun::tcp_reachable(ip, server.port, Duration::from_secs(4))
        .await
        .map_err(|e| format!("Сервер недоступен по TCP: {e}"))?;

    // Ask Xray about the server itself first: a refusal greys the server out.
    if let Verdict::Rejected(reason) = validate::check(core_cfg, server, run_dir).await {
        let _ = tx.send(BgEvent::ServerRejected {
            id: server.id,
            reason: reason.clone(),
        });
        return Err(format!("Xray отверг конфиг сервера: {reason}").into());
    }

    let binary = match &setup {
        Some(s) => s.core.clone(),
        None => resolve_binary(&core_cfg.xray_path).map_err(|e| e.to_string())?,
    };
    let mut plan = tun::build_plan(config, host, mode, (mode == Mode::Tun).then_some(ip));
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
    if let Verdict::Rejected(reason) = validate::check_config(&binary, &cfg, run_dir).await {
        return Err(format!("Xray отверг итоговый конфиг (проверьте правила): {reason}").into());
    }

    let opts = StartOptions {
        binary: setup.as_ref().map(|s| s.core.clone()),
        supervised: setup.as_ref().is_some_and(|s| s.supervised),
        interface: setup.as_ref().map(|s| s.interface.clone()),
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

impl AppState {
    pub(super) fn connect(&mut self, id: u64) {
        if self.busy {
            self.status = Some("Подождите: ядро запускается или останавливается".into());
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
                self.popup = Some(Popup::Confirm {
                    text: "Режим TUN. Включить пресет «только Discord»?\n\nДа: через VPN пойдёт только Discord, всё остальное напрямую.\nНет: через VPN пойдёт всё, кроме локальной сети.\n(Это можно изменить на экране правил, клавиша r.)".into(),
                    kind: ConfirmKind::PresetOffer(id),
                });
                return;
            }
            let preflight = tun::preflight(&*self.tun_host, &self.config);
            if let Some(problem) = preflight.blocking().first() {
                self.remember_server(id);
                self.show_problem(problem);
                return;
            }
            // Warnings (for example a strict rp_filter) do not stop the start.
            if let Some(warning) = preflight.problems.first() {
                self.show_problem(warning);
            }
            setup = preflight.setup;
        }

        self.up_bytes = 0;
        self.down_bytes = 0;
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
            )
            .await;
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

    /// Demo servers (debug builds): no real process.
    fn connect_mock(&mut self, id: u64, server: &Server) {
        self.up_bytes = 0;
        self.down_bytes = 0;
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
        self.spawn_health(id);
    }

    pub(super) fn on_core_failed(&mut self, id: u64, error: String, needs_privileges: bool) {
        self.log(Level::Error, format!("[Error] {error}"));
        if self.conn != Conn::Connecting(id) {
            return;
        }
        self.tun_active = false;
        self.conn = Conn::Error("не удалось запустить ядро".into());
        self.request_proxy_off();
        if needs_privileges {
            self.show_problem(&Problem::NeedsPrivileges);
        } else {
            self.popup = Some(Popup::Error(error));
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
        self.popup = Some(match problem {
            Problem::NeedsPrivileges if cfg!(windows) => Popup::Confirm {
                text,
                kind: ConfirmKind::RestartElevated,
            },
            p if p.is_blocking() => Popup::Error(text),
            _ => Popup::Notice(text),
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
    fn tun_first_run(&self) -> bool {
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

    /// The user said "no" to a question.
    pub(super) fn decline(&mut self, kind: ConfirmKind) {
        match kind {
            ConfirmKind::PresetOffer(id) => {
                self.config.ui.tun_intro_done = true;
                self.save_config();
                self.connect(id);
            }
            ConfirmKind::RestartElevated => {
                self.status = Some("Без прав администратора режим TUN не запустить".into());
            }
            _ => {}
        }
    }

    /// Windows: start elf-gate again with administrator rights, straight into TUN.
    pub(super) fn restart_elevated(&mut self) {
        match platform::privileges().relaunch_elevated(&["--tun".to_string()]) {
            Ok(()) => self.should_quit = true,
            Err(e) => self.popup = Some(Popup::Error(e.to_string())),
        }
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
        if !build_info::TUN_AVAILABLE {
            self.status = Some("Режим TUN в этой версии недоступен".into());
            return;
        }
        self.mode = Mode::Tun;
        self.config.mode.traffic = Mode::Tun;
        let wanted = self.config.ui.last_server.clone();
        let found = self.subs.iter().find_map(|sub| {
            sub.servers
                .iter()
                .find(|s| wanted.as_deref() == Some(&format!("{}/{}", sub.name, s.name)))
                .map(|s| s.id)
        });
        match found {
            Some(id) => self.connect(id),
            None => {
                self.status =
                    Some("Нет сервера для автоподключения: выберите сервер и нажмите Enter".into())
            }
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
    fn tun_app(host: MockTunHost, core_exists: bool, dir: &Path) -> (AppState, u64) {
        let mut config = Config::default();
        config.tun.xray_path = if core_exists {
            let core = dir.join("xray");
            std::fs::write(&core, b"x").unwrap();
            core.display().to_string()
        } else {
            "/definitely/not/here/xray".into()
        };
        let (tx, _rx) = unbounded_channel();
        let mut a = AppState::build(tx, config, None, false).with_tun_host(Arc::new(host));
        a.submit_input("vless://u@10.0.0.5:443?security=none#Real".into());
        a.mode = Mode::Tun;
        a.selected = a.rows().len() - 1;
        let id = a.selected_server().unwrap().id;
        (a, id)
    }

    #[tokio::test]
    async fn first_tun_start_offers_the_discord_preset() {
        let dir = temp_dir("offer");
        let (mut a, id) = tun_app(MockTunHost::healthy(), true, &dir);
        a.connect(id);
        let Some(Popup::Confirm { text, kind }) = &a.popup else {
            panic!("preset offer expected, got {:?}", a.popup)
        };
        assert_eq!(*kind, ConfirmKind::PresetOffer(id));
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
        a.confirm(ConfirmKind::PresetOffer(id));
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
            matches!(a.popup, Some(Popup::Error(_))),
            "the missing core is reported: {:?}",
            a.popup
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn declining_the_offer_keeps_everything_through_the_vpn() {
        let dir = temp_dir("decline");
        let (mut a, id) = tun_app(MockTunHost::healthy(), false, &dir);
        a.decline(ConfirmKind::PresetOffer(id));
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
                    "sudo setcap cap_net_admin+ep"
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
            let text = match &a.popup {
                Some(Popup::Error(t)) => t.clone(),
                other => panic!("an error popup expected for {needle}, got {other:?}"),
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
                a.popup,
                Some(Popup::Confirm {
                    kind: ConfirmKind::RestartElevated,
                    ..
                })
            ));
        } else {
            let Some(Popup::Error(text)) = &a.popup else {
                panic!("{:?}", a.popup)
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
        let mut a = AppState::build(tx, Config::default(), None, false);
        a.decline(ConfirmKind::RestartElevated);
        assert!(a.status.as_deref().unwrap().contains("администратора"));
    }

    #[tokio::test]
    async fn a_start_error_about_permissions_becomes_the_privileges_dialog() {
        let (tx, _rx) = unbounded_channel();
        let mut a = AppState::build(tx, Config::default(), None, false);
        a.submit_input("vless://u@10.0.0.5:443?security=none#Real".into());
        let id = a.subs[0].servers[0].id;
        a.conn = Conn::Connecting(id);
        a.on_core_failed(
            id,
            "ядро завершилось сразу (operation not permitted)".into(),
            true,
        );
        assert!(matches!(a.conn, Conn::Error(_)));
        assert!(a.popup.is_some());
        // An ordinary failure shows the error text itself.
        a.popup = None;
        a.conn = Conn::Connecting(id);
        a.on_core_failed(
            id,
            "порт 10808 (socks) уже занят другой программой".into(),
            false,
        );
        assert!(matches!(&a.popup, Some(Popup::Error(t)) if t.contains("10808")));
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
            matches!(&a.popup, Some(Popup::Notice(t)) if t.contains("sysctl -w") && t.contains("не меняет"))
        );
        assert_eq!(a.conn, Conn::Connecting(id));
        assert!(a.busy);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn connection_check_results_are_shown_and_drive_the_fp_hint() {
        let (tx, _rx) = unbounded_channel();
        let mut a = AppState::build(tx, Config::default(), None, false);
        a.submit_input(
            "vless://u@h.example.com:443?security=reality&sni=x.org&pbk=K&sid=ab&fp=chrome#R"
                .into(),
        );
        let id = a.subs[0].servers[0].id;
        a.conn = Conn::Connected(id);

        a.on_health(id, Ok(Duration::from_millis(80)));
        assert_eq!(a.health, HealthState::Ok(Duration::from_millis(80)));
        assert_eq!(a.fp_hint(), None);

        a.on_health(id, Err("нет ответа за 8 с".into()));
        assert!(matches!(a.health, HealthState::Failed(_)));
        assert!(a.fp_hint().unwrap().contains("fp=firefox"));

        // With firefox already chosen the hint is generic, not a repeat of the same advice.
        a.set_fingerprint(id, Some("firefox".into()));
        a.conn = Conn::Connected(id);
        a.health = HealthState::Failed("нет ответа".into());
        let hint = a.fp_hint().unwrap();
        assert!(
            !hint.contains("fp=firefox") && hint.contains("ключ"),
            "{hint}"
        );

        // Results for a connection that no longer exists are ignored.
        a.conn = Conn::Disconnected;
        a.health = HealthState::Unknown;
        a.on_health(id, Err("late".into()));
        assert_eq!(a.health, HealthState::Unknown);
    }

    #[tokio::test]
    async fn core_log_noise_never_produces_a_hint() {
        let (tx, _rx) = unbounded_channel();
        let mut a = AppState::build(tx, Config::default(), None, false);
        a.submit_input(
            "vless://u@h.example.com:443?security=reality&sni=x.org&pbk=K&sid=ab&fp=chrome#R"
                .into(),
        );
        let id = a.subs[0].servers[0].id;
        a.conn = Conn::Connected(id);
        for _ in 0..10 {
            a.on_bg(BgEvent::Log(LogLine {
                time: "00:00:00".into(),
                level: Level::Warning,
                text: "[xray] [Warning] proxy/vless/outbound: connection ends > EOF".into(),
            }));
        }
        assert_eq!(
            a.fp_hint(),
            None,
            "the hint comes from the connection check, not from log text"
        );
    }

    #[tokio::test]
    async fn tun_toggle_switches_mode_and_remembers_it() {
        let dir = temp_dir("toggle");
        let storage = Storage::new(&dir);
        let (tx, _rx) = unbounded_channel();
        let mut a = AppState::build(tx, Config::default(), Some(storage.clone()), false);
        assert_eq!(a.mode, Mode::Proxy);
        a.handle_action(Action::ToggleMode);
        assert_eq!(a.mode, Mode::Tun);
        assert_eq!(storage.load().unwrap().mode.traffic, Mode::Tun);
        a.handle_action(Action::ToggleMode);
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
        assert!(a.status.as_deref().unwrap().contains("Нет сервера"));

        a.config.ui.last_server = Some("manual/Real".into());
        a.config.ui.tun_intro_done = true;
        a.start_tun_from_cli();
        assert_eq!(a.mode, Mode::Tun);
        // The core is missing in this fixture: the start stops at the problem popup.
        assert!(matches!(a.popup, Some(Popup::Error(_))));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn startup_cleans_up_a_core_left_by_a_crash() {
        let dir = temp_dir("cleanup");
        let store = StateStore::new(&dir);
        tun::mark_up(&store, 777, "elfgate0");
        let host = Arc::new(MockTunHost::healthy());
        let (tx, _rx) = unbounded_channel();
        let mut a = AppState::build(tx, Config::default(), None, false)
            .with_state_store(store.clone())
            .with_tun_host(host.clone());
        let note = a.startup_tun_cleanup().unwrap();
        assert!(note.contains("остановлен"), "{note}");
        assert_eq!(host.killed.lock().unwrap().as_slice(), &[777]);
        assert!(store.load().unwrap().tun.is_none());
        assert!(a.logs.iter().any(|l| l.text.contains("TUN:")));
        let _ = std::fs::remove_dir_all(dir);
    }
}
