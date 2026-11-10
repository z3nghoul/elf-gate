//! The engine: everything that owns resources. It runs inside the background process
//! (`elf-gated`) and holds the servers, the Xray core, the system proxy and the TUN, the
//! configuration and the recovery state. The interface only sends it [`Cmd`]s and draws the
//! [`View`] it publishes.

use crate::event::{now_hms, BgEvent, BgTx, Level, LogLine};
use crate::mock::{self, Lcg};
use crate::model::rule::{builtin_presets, bypass_additions, effective_rules, Rule, RuleKind};
use crate::model::server::{Ping, Server};
use crate::model::subscription::Subscription;
use crate::parser;
use crate::platform::{ProxyAddr, TunHost};
use crate::proto::{Alert, Ask, Cmd, Conn, HealthState, RuleRef, Traffic, Update, View};
use crate::storage::{Config, ServerEntry, ServerOverride, StateStore, Storage};
use crate::sysproxy::{ProxyCmd, ProxyHandle};
use crate::xray::checkcache::Checker;
use crate::xray::process::Core;
use crate::xray::validate::Verdict;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, watch};

mod ping;
mod rules;
mod server_opts;
mod session;
mod subs;

pub use crate::model::rule::TrafficMode as Mode;

pub const LOG_CAPACITY: usize = 2000;
/// Name of the group holding servers added by hand (persisted in `config.toml`).
pub const MANUAL_GROUP: &str = "manual";

/// What the background process publishes: the latest [`View`], a stream of log lines, alerts
/// and status texts, and the log history for newcomers.
pub struct Hub {
    logs: Mutex<VecDeque<LogLine>>,
    view_tx: watch::Sender<Arc<View>>,
    events_tx: broadcast::Sender<Update>,
}

/// A client's subscription to the hub.
pub struct Feed {
    pub backlog: Vec<LogLine>,
    pub view: watch::Receiver<Arc<View>>,
    pub events: broadcast::Receiver<Update>,
}

impl Hub {
    pub fn new(initial: View) -> Arc<Self> {
        let (view_tx, _) = watch::channel(Arc::new(initial));
        let (events_tx, _) = broadcast::channel(2048);
        Arc::new(Self {
            logs: Mutex::new(VecDeque::with_capacity(LOG_CAPACITY)),
            view_tx,
            events_tx,
        })
    }

    pub fn subscribe(&self) -> Feed {
        // Take the backlog and the receiver under one lock so no line is lost or doubled.
        let logs = self.logs.lock().unwrap();
        Feed {
            backlog: logs.iter().cloned().collect(),
            view: self.view_tx.subscribe(),
            events: self.events_tx.subscribe(),
        }
    }

    fn push_log(&self, line: LogLine) {
        let mut logs = self.logs.lock().unwrap();
        if logs.len() == LOG_CAPACITY {
            logs.pop_front();
        }
        logs.push_back(line.clone());
        let _ = self.events_tx.send(Update::Log(line));
    }

    fn emit(&self, update: Update) {
        let _ = self.events_tx.send(update);
    }
}

pub struct Engine {
    pub subs: Vec<Subscription>,
    pub mode: Mode,
    pub conn: Conn,
    pub health: HealthState,
    /// What the current connection runs in (the mode may be toggled meanwhile).
    pub conn_mode: Mode,
    /// A TUN core is running.
    pub tun_active: bool,
    pub config: Config,
    /// The worker reported the system proxy as switched on.
    pub proxy_active: bool,
    pub traffic: Traffic,
    /// Demo data and fake numbers are enabled (debug builds).
    pub mock: bool,
    /// A tray icon is shown by this process.
    pub tray: bool,
    /// Set by `Cmd::Shutdown`: the process should stop after cleaning up.
    pub should_exit: bool,
    /// Set by `Cmd::RelaunchElevated`: the process should restart with administrator rights.
    pub relaunch_elevated: bool,
    tun_host: Arc<dyn TunHost>,
    state_store: Option<StateStore>,
    storage: Option<Storage>,
    /// The running Xray process, if any.
    core: Option<Core>,
    proxy: Option<ProxyHandle>,
    /// We asked the worker to switch the system proxy on and have not asked to undo it.
    proxy_requested: bool,
    /// The bypass list the system proxy was last given.
    proxy_bypass_sent: Vec<String>,
    /// A core start or stop is in flight; new connect requests wait for it.
    busy: bool,
    run_dir: PathBuf,
    /// Cached, rate-limited `xray run -test`.
    checker: Arc<Checker>,
    /// Subscriptions being downloaded right now (by name).
    updating: HashSet<String>,
    /// Servers whose fingerprint search is running.
    fp_searching: HashSet<u64>,
    last_auto_check: Option<Instant>,
    /// When a subscription's update last failed (not retried for ten minutes).
    failed_at: HashMap<String, Instant>,
    autostart_on: bool,
    next_id: u64,
    tx: BgTx,
    rng: Lcg,
    hub: Arc<Hub>,
    last_view: Option<String>,
    #[cfg(test)]
    pub sent: Vec<Update>,
}

impl Engine {
    /// In-memory engine with default config and no persistence (tests).
    #[cfg(test)]
    pub fn new(tx: BgTx) -> Self {
        Self::build(tx, Config::default(), None, false)
    }

    pub fn with_config(tx: BgTx, config: Config, storage: Option<Storage>) -> Self {
        Self::build(tx, config, storage, crate::build_info::demo_data())
    }

    /// `mock`: demo servers, fake pings and traffic (debug builds only, see `build_info`).
    pub(crate) fn build(tx: BgTx, config: Config, storage: Option<Storage>, mock: bool) -> Self {
        let mut next_id = 0;
        let mut subs = if mock {
            mock::subscriptions(&mut next_id)
        } else {
            Vec::new()
        };
        let mut load_errors = Vec::new();
        let cache = storage
            .as_ref()
            .map(|st| st.load_subscriptions())
            .unwrap_or_default();
        subs.extend(Self::subscription_groups(
            &config,
            &cache,
            &mut next_id,
            &mut load_errors,
        ));
        let mut manual = Vec::new();
        for entry in &config.servers {
            match parser::parse_link(&entry.link) {
                Ok(mut server) => {
                    next_id += 1;
                    server.id = next_id;
                    manual.push(server);
                }
                Err(e) => load_errors.push(format!("{}: {e}", entry.link)),
            }
        }
        if !manual.is_empty() {
            subs.push(Subscription {
                name: MANUAL_GROUP.into(),
                servers: manual,
                collapsed: false,
                info: None,
                updated: None,
                is_remote: false,
            });
        }
        for sub in &mut subs {
            let group = sub.name.clone();
            for server in &mut sub.servers {
                apply_overrides(&config, &group, server);
            }
        }
        let initial_view = View {
            groups: Vec::new(),
            conn: Conn::Disconnected,
            mode: config.mode.traffic,
            conn_mode: config.mode.traffic,
            tun_active: false,
            proxy_active: false,
            health: HealthState::Unknown,
            config: config.redacted(),
            traffic: Traffic::default(),
            tray: false,
            autostart: false,
            mock,
            pid: std::process::id(),
        };
        let mut engine = Self {
            subs,
            mode: config.mode.traffic,
            conn: Conn::Disconnected,
            health: HealthState::Unknown,
            conn_mode: config.mode.traffic,
            tun_active: false,
            config,
            proxy_active: false,
            traffic: Traffic::default(),
            mock,
            tray: false,
            should_exit: false,
            relaunch_elevated: false,
            tun_host: Arc::from(crate::platform::tun_host()),
            state_store: None,
            storage,
            core: None,
            proxy: None,
            proxy_requested: false,
            proxy_bypass_sent: Vec::new(),
            busy: false,
            run_dir: std::env::temp_dir().join("elf-gate-run"),
            checker: Checker::new(None),
            updating: HashSet::new(),
            fp_searching: HashSet::new(),
            last_auto_check: None,
            failed_at: HashMap::new(),
            autostart_on: false,
            next_id,
            tx,
            rng: Lcg::from_clock(),
            hub: Hub::new(initial_view),
            last_view: None,
            #[cfg(test)]
            sent: Vec::new(),
        };
        engine.log(
            Level::Info,
            if mock {
                "elf-gated started (debug build: demo servers are mock data)"
            } else {
                "elf-gated started"
            },
        );
        for e in load_errors {
            engine.log(Level::Warning, format!("skipped saved server, {e}"));
        }
        engine
    }

    pub fn hub(&self) -> Arc<Hub> {
        self.hub.clone()
    }

    /// Directory for generated core configs (`run/`).
    pub fn with_run_dir(mut self, dir: PathBuf) -> Self {
        self.run_dir = dir;
        self
    }

    pub fn with_state_store(mut self, store: StateStore) -> Self {
        self.state_store = Some(store);
        self
    }

    /// Keeps `xray run -test` verdicts in `path` between runs.
    pub fn with_check_cache(mut self, path: PathBuf) -> Self {
        self.checker = Checker::new(Some(path));
        self
    }

    #[cfg(test)]
    pub fn with_tun_host(mut self, host: Arc<dyn TunHost>) -> Self {
        self.tun_host = host;
        self
    }

    pub fn with_proxy(mut self, handle: ProxyHandle) -> Self {
        self.proxy = Some(handle);
        self
    }

    pub fn with_tray(mut self, present: bool) -> Self {
        self.tray = present;
        self
    }

    pub fn with_autostart(mut self, on: bool) -> Self {
        self.autostart_on = on;
        self
    }

    /// PID of the running core (tests use it to simulate a crash).
    #[cfg(all(test, unix))]
    pub(crate) fn core_pid(&self) -> Option<u32> {
        self.core.as_ref().and_then(|c| c.pid())
    }

    /// Restores the system proxy and stops the core before the process exits.
    pub async fn shutdown(&mut self) {
        if let Some(handle) = &self.proxy {
            let controller = handle.controller.clone();
            let _ = tokio::task::spawn_blocking(move || controller.close()).await;
            self.proxy_active = false;
        }
        if let Some(core) = self.core.take() {
            core.stop().await;
            if let Some(store) = &self.state_store {
                crate::tun::mark_down(store);
            }
            self.tun_active = false;
        }
        self.conn = Conn::Disconnected;
        self.hub.emit(Update::Bye);
    }

    // ---------- output ----------

    fn emit(&mut self, update: Update) {
        #[cfg(test)]
        self.sent.push(update.clone());
        self.hub.emit(update);
    }

    pub fn log(&mut self, level: Level, text: impl Into<String>) {
        let text = text.into();
        // Application lines (never the core's traffic log) also go to the log file,
        // so a tester can attach it to a bug report.
        tracing::info!(target: "app", "{text}");
        self.push_log(LogLine {
            time: now_hms(),
            level,
            text,
        });
    }

    fn push_log(&mut self, line: LogLine) {
        #[cfg(test)]
        self.sent.push(Update::Log(line.clone()));
        self.hub.push_log(line);
    }

    fn alert(&mut self, alert: Alert) {
        self.emit(Update::Alert(alert));
    }

    fn error_alert(&mut self, text: impl Into<String>) {
        self.alert(Alert::Error(text.into()));
    }

    pub(crate) fn status(&mut self, text: impl Into<String>) {
        self.emit(Update::Status(text.into()));
    }

    #[cfg(test)]
    pub(crate) fn alerts(&self) -> Vec<Alert> {
        self.sent
            .iter()
            .filter_map(|u| match u {
                Update::Alert(a) => Some(a.clone()),
                _ => None,
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn last_status(&self) -> Option<String> {
        self.sent.iter().rev().find_map(|u| match u {
            Update::Status(s) => Some(s.clone()),
            _ => None,
        })
    }

    #[cfg(test)]
    pub(crate) fn logged(&self, needle: &str) -> bool {
        self.sent
            .iter()
            .any(|u| matches!(u, Update::Log(l) if l.text.contains(needle)))
    }

    /// The snapshot the interface draws.
    pub fn view(&self) -> View {
        View {
            groups: self
                .subs
                .iter()
                .map(|g| Subscription {
                    servers: g.servers.iter().map(Server::redacted).collect(),
                    ..g.clone()
                })
                .collect(),
            conn: self.conn.clone(),
            mode: self.mode,
            conn_mode: self.conn_mode,
            tun_active: self.tun_active,
            proxy_active: self.proxy_active,
            health: self.health.clone(),
            config: self.config.redacted(),
            traffic: self.traffic.clone(),
            tray: self.tray,
            autostart: self.autostart_on,
            mock: self.mock,
            pid: std::process::id(),
        }
    }

    /// Publishes the view if it changed since the last time.
    pub fn flush_view(&mut self) {
        let view = self.view();
        let Ok(json) = serde_json::to_string(&view) else {
            return;
        };
        if self.last_view.as_deref() == Some(json.as_str()) {
            return;
        }
        self.last_view = Some(json);
        let _ = self.hub.view_tx.send(Arc::new(view));
    }

    // ---------- proxy ----------

    /// Points the system proxy at the local core, if the user wants that and it can work.
    fn request_proxy_on(&mut self) {
        let Some(handle) = &self.proxy else { return };
        if !self.config.proxy.set_system_proxy || self.conn_mode != Mode::Proxy {
            return;
        }
        let bypass = self.proxy_bypass();
        // Already on with the same list: nothing to do. Rules may have changed: send it again
        // (the controller keeps the user's original settings across repeated enables).
        if self.proxy_requested && self.proxy_bypass_sent == bypass {
            return;
        }
        let core = &self.config.core;
        if !handle.controller.is_supported() {
            let hint = format!(
                "Системный прокси не поддерживается в этом окружении. Настройте вручную: \
                 SOCKS5 127.0.0.1:{}, HTTP 127.0.0.1:{}. Либо используйте режим TUN (t).",
                core.socks_port, core.http_port
            );
            self.log(Level::Warning, hint.clone());
            self.status(hint);
            return;
        }
        let handle = self.proxy.as_ref().expect("checked above");
        let core = &self.config.core;
        handle.send(ProxyCmd::Enable {
            addr: ProxyAddr {
                host: "127.0.0.1".into(),
                socks_port: core.socks_port,
                http_port: core.http_port,
            },
            bypass: bypass.clone(),
        });
        self.proxy_bypass_sent = bypass;
        self.proxy_requested = true;
    }

    /// `[proxy].bypass` plus plain domains and IPs of the "direct" rules (exclude mode).
    pub(crate) fn proxy_bypass(&self) -> Vec<String> {
        let rules = effective_rules(
            self.config.mode.routing,
            &self.config.rules,
            &self.config.presets.enabled,
            &builtin_presets(),
            cfg!(windows),
        );
        let mut bypass = self.config.proxy.bypass.clone();
        for extra in bypass_additions(self.config.mode.routing, &rules) {
            if !bypass.contains(&extra) {
                bypass.push(extra);
            }
        }
        bypass
    }

    /// Puts the user's own proxy settings back.
    fn request_proxy_off(&mut self) {
        if self.proxy_requested {
            if let Some(handle) = &self.proxy {
                handle.send(ProxyCmd::Disable);
            }
            self.proxy_requested = false;
        }
    }

    // ---------- lookup ----------

    pub fn server_by_id(&self, id: u64) -> Option<&Server> {
        self.subs
            .iter()
            .flat_map(|s| s.servers.iter())
            .find(|s| s.id == id)
    }

    // ---------- events ----------

    /// One tick (the loop calls it about four times a second).
    pub fn on_tick(&mut self) {
        self.poll_core();
        self.auto_update_tick();
        if self.mock && matches!(self.conn, Conn::Connected(_)) {
            self.traffic.proxy_up += self.rng.next() % 2_000;
            self.traffic.proxy_down += self.rng.next() % 20_000;
        }
        self.flush_view();
    }

    pub fn on_bg(&mut self, ev: BgEvent) {
        match ev {
            BgEvent::Log(line) => self.push_log(line),
            BgEvent::Ping { id, result } => {
                if let Some(s) = self
                    .subs
                    .iter_mut()
                    .flat_map(|s| s.servers.iter_mut())
                    .find(|s| s.id == id)
                {
                    s.ping = result;
                }
            }
            BgEvent::Connected(id) => {
                if self.conn == Conn::Connecting(id) {
                    self.conn = Conn::Connected(id);
                    let name = self.server_by_id(id).map(|s| s.name.clone());
                    self.log(
                        Level::Info,
                        format!("connected to {}", name.unwrap_or_default()),
                    );
                }
            }
            BgEvent::CoreStarted { id, core } => {
                self.busy = false;
                if self.conn == Conn::Connecting(id) {
                    self.on_core_started(id, *core);
                } else {
                    // The user cancelled while the core was starting.
                    self.spawn_stop(*core);
                }
            }
            BgEvent::CoreFailed {
                id,
                error,
                needs_privileges,
            } => {
                self.busy = false;
                self.on_core_failed(id, error, needs_privileges);
            }
            BgEvent::Health { id, result } => self.on_health(id, result),
            BgEvent::CoreStopped => self.busy = false,
            BgEvent::ProxyChanged { active, error } => match error {
                None => {
                    self.proxy_active = active;
                    let msg = if active {
                        "system proxy enabled"
                    } else {
                        "system proxy restored"
                    };
                    self.log(Level::Info, msg);
                }
                Some(e) => {
                    self.proxy_active = false;
                    self.proxy_requested = false;
                    self.log(Level::Error, format!("[Error] system proxy: {e}"));
                    self.error_alert(format!("Системный прокси: {e}"));
                }
            },
            BgEvent::ServerRejected { id, reason } => self.mark_rejected(id, &reason),
            BgEvent::ConnectFailed { id, reason } => {
                if self.conn == Conn::Connecting(id) {
                    self.conn = Conn::Error("не удалось подключиться".into());
                    self.log(Level::Error, format!("[Error] {reason}"));
                    self.error_alert(reason);
                }
            }
            BgEvent::FpSuspect { id } => self.on_fp_suspect(id),
            BgEvent::FpSearched {
                id,
                xray_version,
                found,
                skipped,
            } => self.on_fp_searched(id, xray_version, found, skipped),
            BgEvent::SubFetched { name, result } => self.on_sub_fetched(name, result),
            BgEvent::SubAdded {
                url,
                user_agent,
                result,
            } => self.on_sub_added(url, user_agent, result),
        }
    }

    // ---------- commands ----------

    pub fn handle_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Connect(id) => self.connect_checked(id),
            Cmd::Disconnect => self.disconnect(),
            Cmd::ToggleMode => self.toggle_mode(),
            Cmd::PingAll => self.ping_all(),
            Cmd::UpdateSubs => self.update_subscriptions(),
            Cmd::AddLink(text) => self.add_link(text),
            Cmd::DeleteServer(id) => self.delete_server(id),
            Cmd::DeleteGroup(name) => self.delete_group(&name),
            Cmd::SetFingerprint { id, fp } => self.set_fingerprint(id, fp),
            Cmd::SetRole { id, role } => self.set_role(id, role),
            Cmd::SetFragment { id, on } => self.set_fragment(id, on),
            Cmd::ToggleRule(item) => self.rules_toggle(item),
            Cmd::DeleteRule(i) => self.rules_delete(i),
            Cmd::AddRule { kind, value } => self.submit_rule(kind, value),
            Cmd::SetRouting(mode) => self.rules_set_routing(mode),
            Cmd::Answer { ask, yes } => self.answer(ask, yes),
            Cmd::Set(setting) => self.apply_setting(setting),
            Cmd::ConnectLastInTun => self.start_tun_from_cli(),
            Cmd::RelaunchElevated => self.restart_elevated(),
            Cmd::Shutdown => self.should_exit = true,
        }
        self.flush_view();
    }

    fn answer(&mut self, ask: Ask, yes: bool) {
        match (ask, yes) {
            (Ask::PresetOffer(id), true) => {
                self.accept_discord_preset();
                self.connect(id);
            }
            (Ask::PresetOffer(id), false) => {
                self.config.ui.tun_intro_done = true;
                self.save_config();
                self.connect(id);
            }
            (Ask::RelaunchElevated, true) => self.restart_elevated(),
            (Ask::RelaunchElevated, false) => {
                self.status("Без прав администратора режим TUN не запустить");
            }
            (Ask::ApplyRules(id), true) => self.connect(id),
            (Ask::ApplyRules(_), false) => {}
        }
    }

    /// `Cmd::Connect`: unsupported servers are explained instead of started.
    fn connect_checked(&mut self, id: u64) {
        let Some(server) = self.server_by_id(id) else {
            return;
        };
        if let Some(reason) = &server.unsupported {
            let msg = format!("«{}»: {reason}", server.name);
            self.error_alert(msg);
            return;
        }
        self.connect(id);
    }

    pub fn disconnect(&mut self) {
        if self.conn == Conn::Disconnected {
            return;
        }
        // A core that is still starting is stopped when its start result arrives.
        if let Some(core) = self.core.take() {
            self.spawn_stop(core);
        }
        self.conn = Conn::Disconnected;
        self.tun_active = false;
        self.log(Level::Info, "disconnected");
        self.request_proxy_off();
    }

    /// Detects a core that died on its own.
    fn poll_core(&mut self) {
        let Some(core) = &mut self.core else { return };
        let Some(info) = core.try_exit() else { return };
        self.core = None;
        self.tun_active = false;
        if let Some(store) = &self.state_store {
            crate::tun::mark_down(store);
        }
        self.request_proxy_off();
        self.conn = Conn::Error("ядро завершилось".into());
        self.log(
            Level::Error,
            format!(
                "[Error] core exited ({}) {}",
                info.code,
                info.tail.replace('\n', " | ")
            ),
        );
        let last: Vec<&str> = info.tail.lines().rev().take(6).collect();
        let last = last.into_iter().rev().collect::<Vec<_>>().join("\n");
        self.error_alert(format!("Ядро Xray завершилось ({}).\n\n{last}", info.code));
    }

    fn toggle_mode(&mut self) {
        let next = match self.mode {
            Mode::Proxy => Mode::Tun,
            Mode::Tun => Mode::Proxy,
        };
        if next == Mode::Tun && !crate::build_info::TUN_AVAILABLE {
            self.status("Режим TUN в этой версии недоступен");
            return;
        }
        self.mode = next;
        self.config.mode.traffic = next;
        self.save_config();
        self.log(Level::Info, format!("mode: {}", mode_name(self.mode)));
        if self.mode == Mode::Tun {
            // TUN needs no system proxy.
            self.request_proxy_off();
        }
        // Switching the mode while connected restarts the connection in the new mode.
        if let Conn::Connected(id) | Conn::Connecting(id) = self.conn {
            self.connect(id);
        }
    }

    // ---------- adding and removing ----------

    pub(crate) fn add_link(&mut self, text: String) {
        let text = text.trim().to_string();
        if text.starts_with("http://") || text.starts_with("https://") {
            self.add_subscription_url(text);
            return;
        }
        match parser::parse_link(&text) {
            Ok(server) => self.add_manual_server(server),
            Err(e) => {
                self.log(Level::Warning, format!("bad link: {e}"));
                self.error_alert(e.to_string());
            }
        }
    }

    fn add_manual_server(&mut self, mut server: Server) {
        if self.config.servers.iter().any(|e| e.link == server.link) {
            self.error_alert("Этот сервер уже добавлен");
            return;
        }
        self.next_id += 1;
        server.id = self.next_id;
        apply_overrides(&self.config, MANUAL_GROUP, &mut server);
        self.config.servers.push(ServerEntry {
            link: server.link.clone(),
        });
        let name = server.name.clone();
        if server.is_supported() {
            self.spawn_checks(vec![server.clone()]);
        }
        match self.subs.iter_mut().find(|s| s.name == MANUAL_GROUP) {
            Some(sub) => sub.servers.push(server),
            None => self.subs.push(Subscription {
                name: MANUAL_GROUP.into(),
                servers: vec![server],
                collapsed: false,
                info: None,
                updated: None,
                is_remote: false,
            }),
        }
        self.log(Level::Info, format!("added server {name}"));
        self.status(format!("Добавлен: {name}"));
        self.save_config();
    }

    pub(crate) fn delete_server(&mut self, id: u64) {
        self.drop_connection_if(|c| c == id);
        let mut removed_links = Vec::new();
        for sub in &mut self.subs {
            if sub.name == MANUAL_GROUP {
                removed_links.extend(
                    sub.servers
                        .iter()
                        .filter(|s| s.id == id)
                        .map(|s| s.link.clone()),
                );
            }
            sub.servers.retain(|s| s.id != id);
        }
        self.subs.retain(|s| !s.servers.is_empty() || s.is_remote);
        if !removed_links.is_empty() {
            self.config
                .servers
                .retain(|e| !removed_links.contains(&e.link));
            self.save_config();
        }
    }

    pub(crate) fn delete_group(&mut self, name: &str) {
        let Some(i) = self.subs.iter().position(|s| s.name == name) else {
            return;
        };
        let ids: Vec<u64> = self.subs[i].servers.iter().map(|s| s.id).collect();
        self.drop_connection_if(|c| ids.contains(&c));
        let was_manual = name == MANUAL_GROUP;
        let was_remote = self.subs[i].is_remote;
        self.subs.remove(i);
        if was_manual {
            self.config.servers.clear();
            self.save_config();
        } else if was_remote {
            self.config.subscriptions.retain(|s| s.name != name);
            self.save_config();
            self.save_subscription_cache();
        }
    }

    fn drop_connection_if(&mut self, f: impl Fn(u64) -> bool) {
        if let Conn::Connected(id) | Conn::Connecting(id) = self.conn {
            if f(id) {
                self.disconnect();
            }
        }
    }

    /// Greys the server out and keeps Xray's error text for the details pane.
    fn mark_rejected(&mut self, id: u64, reason: &str) {
        let mut name = None;
        for server in self
            .subs
            .iter_mut()
            .flat_map(|s| s.servers.iter_mut())
            .filter(|s| s.id == id)
        {
            server.unsupported = Some(format!("Xray отверг конфиг: {reason}"));
            name = Some(server.name.clone());
        }
        if let Some(name) = name {
            self.log(
                Level::Warning,
                format!("[Warning] {name}: Xray отверг конфиг: {reason}"),
            );
        }
    }

    // ---------- checks ----------

    /// Checks the given servers with `xray run -test` in the background (at most four
    /// processes at once, verdicts come from the cache when the config was seen before).
    fn spawn_checks(&self, servers: Vec<Server>) {
        if servers.is_empty() {
            return;
        }
        let tx = self.tx.clone();
        let core_cfg = self.config.core.clone();
        let run_dir = self.run_dir.clone();
        let checker = self.checker.clone();
        tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            for server in servers {
                let (tx, core_cfg, run_dir, checker) = (
                    tx.clone(),
                    core_cfg.clone(),
                    run_dir.clone(),
                    checker.clone(),
                );
                tasks.spawn(async move {
                    match checker.check(&core_cfg, &server, &run_dir).await {
                        Verdict::Accepted => {}
                        Verdict::Rejected(reason) => {
                            let _ = tx.send(BgEvent::ServerRejected {
                                id: server.id,
                                reason,
                            });
                        }
                        Verdict::Unavailable(why) => {
                            // Not Xray's verdict on the server (e.g. no binary yet): say so once.
                            if checker.first_unavailable() {
                                let _ = tx.send(BgEvent::Log(LogLine {
                                    time: now_hms(),
                                    level: Level::Info,
                                    text: format!("server validation skipped: {why}"),
                                }));
                            }
                        }
                    }
                });
            }
            while tasks.join_next().await.is_some() {}
            checker.flush();
        });
    }

    /// Validates every imported server that has a real link. Call once after the
    /// run directory is set.
    pub fn start_background_checks(&self) {
        let servers: Vec<Server> = self
            .subs
            .iter()
            .flat_map(|s| s.servers.iter())
            .filter(|s| !s.link.is_empty() && s.is_supported())
            .cloned()
            .collect();
        self.spawn_checks(servers);
    }

    fn save_config(&mut self) {
        let Some(storage) = &self.storage else { return };
        if let Err(e) = storage.save(&self.config) {
            self.log(Level::Error, format!("[Error] {e}"));
            self.error_alert(e.to_string());
        }
    }

    /// Edits (creating if needed) the `[[overrides]]` entry for `key`; an entry that no longer
    /// overrides anything is removed.
    pub(crate) fn update_override(&mut self, key: &str, edit: impl FnOnce(&mut ServerOverride)) {
        let pos = self.config.overrides.iter().position(|o| o.server == key);
        let mut entry = match pos {
            Some(i) => self.config.overrides.remove(i),
            None => ServerOverride::new(key.to_string()),
        };
        edit(&mut entry);
        if !entry.is_empty() {
            match pos {
                Some(i) => self.config.overrides.insert(i, entry),
                None => self.config.overrides.push(entry),
            }
        }
    }

    /// `(group, override key)` of a server.
    pub(crate) fn server_key_of(&self, id: u64) -> Option<(String, String)> {
        self.subs.iter().find_map(|sub| {
            sub.servers
                .iter()
                .find(|s| s.id == id)
                .map(|s| (sub.name.clone(), override_key(&sub.name, s)))
        })
    }

    // ---------- fingerprint ----------

    /// Stores (or clears, with `None`) the fingerprint override and restarts the core if
    /// it is running this server, so the change takes effect at once.
    pub(crate) fn set_fingerprint(&mut self, id: u64, fp: Option<String>) {
        let mut found = None;
        for sub in &mut self.subs {
            let group = sub.name.clone();
            if let Some(server) = sub.servers.iter_mut().find(|s| s.id == id) {
                server.fp_override = fp.clone();
                server.fp_auto = false;
                found = Some((override_key(&group, server), server.name.clone()));
            }
        }
        let Some((key, name)) = found else { return };
        self.update_override(&key, |o| {
            o.fp = fp.clone();
            o.fp_auto = false;
        });
        self.log(
            Level::Info,
            format!(
                "fp for {name}: {}",
                fp.as_deref().unwrap_or("as in the link")
            ),
        );
        self.save_config();
        if matches!(self.conn, Conn::Connected(c) | Conn::Connecting(c) if c == id) {
            if self.busy {
                self.status("fp сохранён, применится при следующем подключении");
            } else {
                self.connect(id);
            }
        }
    }

    // ---------- settings (stage 8) ----------

    fn apply_setting(&mut self, setting: crate::proto::Setting) {
        use crate::proto::Setting::*;
        let port_ok = |p: u16| p >= 1024;
        match setting {
            XrayPath(v) => self.config.core.xray_path = v,
            TunXrayPath(v) => self.config.tun.xray_path = v,
            SocksPort(p) | HttpPort(p) | ApiPort(p) if !port_ok(p) => {
                self.error_alert("Порт должен быть от 1024 до 65535");
                return;
            }
            SocksPort(p) => self.config.core.socks_port = p,
            HttpPort(p) => self.config.core.http_port = p,
            ApiPort(p) => self.config.core.api_port = p,
            LogLevel(v) => {
                if !["debug", "info", "warning", "error", "none"].contains(&v.as_str()) {
                    self.error_alert("Уровень лога: debug, info, warning, error или none");
                    return;
                }
                self.config.core.log_level = v;
            }
            SetSystemProxy(v) => self.config.proxy.set_system_proxy = v,
            PingMode(m) => self.config.ping.mode = m,
            PingUrl(v) => self.config.ping.url = v,
            PingTimeoutMs(v) => self.config.ping.timeout_ms = v.clamp(500, 30_000),
            PingAutoIntervalSecs(v) => self.config.ping.auto_interval_secs = v,
            TunName(v) => {
                if v.is_empty() || v.len() > 15 {
                    self.error_alert("Имя интерфейса: от 1 до 15 символов");
                    return;
                }
                self.config.tun.name = v;
            }
            TunnelDns(v) => self.config.tun.tunnel_dns = v,
            AutoConnect(v) => self.config.ui.auto_connect = v,
            Theme(v) => {
                if v != "dark" && v != "light" {
                    return;
                }
                self.config.ui.theme = v;
            }
            Autostart(on) => {
                let result = if on {
                    crate::ipc::Spawn::default_for_current_exe()
                        .map(|sp| {
                            let mut cmd = vec![sp.program.display().to_string()];
                            cmd.extend(sp.args);
                            cmd
                        })
                        .ok_or_else(|| "не найден путь к программе".to_string())
                        .and_then(|cmd| {
                            crate::platform::autostart()
                                .enable(&cmd)
                                .map_err(|e| e.to_string())
                        })
                } else {
                    crate::platform::autostart()
                        .disable()
                        .map_err(|e| e.to_string())
                };
                match result {
                    Ok(()) => self.autostart_on = on,
                    Err(e) => {
                        self.error_alert(format!("Автозапуск: {e}"));
                        return;
                    }
                }
                self.log(
                    Level::Info,
                    format!("автозапуск при входе: {}", if on { "вкл" } else { "выкл" }),
                );
                return;
            }
            SubscriptionUserAgent { name, value } => {
                if let Some(s) = self
                    .config
                    .subscriptions
                    .iter_mut()
                    .find(|s| s.name == name)
                {
                    s.user_agent = value;
                }
            }
            SubscriptionHours { name, hours } => {
                if let Some(s) = self
                    .config
                    .subscriptions
                    .iter_mut()
                    .find(|s| s.name == name)
                {
                    s.auto_update_hours = hours;
                }
            }
        }
        self.save_config();
        self.status("Настройка сохранена (порты и пути применятся при следующем подключении)");
    }
}

/// Stable identity of a server for per-server overrides: `"<group>/<name>|<host>:<port>"`.
pub fn override_key(group: &str, server: &Server) -> String {
    format!("{group}/{}|{}:{}", server.name, server.address, server.port)
}

/// Copies the per-server settings from `[[overrides]]` onto a freshly created server.
pub(crate) fn apply_overrides(config: &Config, group: &str, server: &mut Server) {
    let key = override_key(group, server);
    let found = config.overrides.iter().find(|o| o.server == key);
    server.fp_override = found.and_then(|o| o.fp.clone());
    server.fp_auto = found.is_some_and(|o| o.fp_auto);
    server.fragment = found.is_some_and(|o| o.fragment);
    server.role = found.and_then(|o| o.role);
}

#[cfg(test)]
mod settings_tests {
    use super::*;
    use crate::proto::Setting;
    use tokio::sync::mpsc::unbounded_channel;

    #[tokio::test]
    async fn settings_are_validated_applied_and_saved() {
        let dir = std::env::temp_dir().join(format!("elf-gate-set-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (tx, _rx) = unbounded_channel();
        let mut e = Engine::build(tx, Config::default(), Some(Storage::new(&dir)), false);
        e.handle_cmd(Cmd::Set(Setting::SocksPort(80)));
        assert_eq!(e.config.core.socks_port, 10808);
        assert!(matches!(e.alerts().last(), Some(Alert::Error(_))));
        e.handle_cmd(Cmd::Set(Setting::SocksPort(2000)));
        e.handle_cmd(Cmd::Set(Setting::Theme("light".into())));
        e.handle_cmd(Cmd::Set(Setting::PingAutoIntervalSecs(0)));
        e.handle_cmd(Cmd::Set(Setting::LogLevel("loud".into())));
        assert_eq!(e.config.core.log_level, "warning");
        let saved = Storage::new(&dir).load().unwrap();
        assert_eq!(saved.core.socks_port, 2000);
        assert_eq!(saved.ui.theme, "light");
        assert_eq!(saved.ping.auto_interval_secs, 0);
        let _ = std::fs::remove_dir_all(dir);
    }
}

pub fn mode_name(m: Mode) -> &'static str {
    match m {
        Mode::Proxy => "PROXY",
        Mode::Tun => "TUN",
    }
}
