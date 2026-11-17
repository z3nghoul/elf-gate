//! Connecting, TUN mode, the connection check, first-run questions, privileges.

use super::*;
use crate::net::health::{self, HealthError};
use crate::storage::{CoreConfig, PresetsConfig};
use crate::tun::{self, Problem};
use crate::xray::config::{build_with, Failover};
use crate::xray::geodata::{drop_missing, Geo};
use crate::xray::process::{resolve_binary, StartOptions};
use std::path::Path;

/// Why a start failed, in words for the user.
#[derive(Debug)]
struct Failure {
    message: String,
    needs_privileges: bool,
    /// This machine's firewall, antivirus or another VPN refused the connection (10013).
    local_block: bool,
    /// TUN mode: the adapter or the interface could not be set up (not a rights problem).
    tun_failed: bool,
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Failure {
            message,
            needs_privileges: false,
            local_block: false,
            tun_failed: false,
        }
    }
}

/// What a core start error means: `(needs_privileges, tun_failed)`. The core is the last step
/// of a start, so in TUN mode what it cannot start (the adapter, the driver library, the
/// interface) is a TUN problem; a missing right is not: that one has its own dialog.
fn classify_start_error(mode: Mode, text: &str) -> (bool, bool) {
    let needs_privileges = mode == Mode::Tun && tun::looks_like_missing_privileges(text);
    (needs_privileges, mode == Mode::Tun && !needs_privileges)
}

/// The first non-empty line of a start error, short enough for a one-line notice.
fn short_reason(error: &str) -> String {
    let line = error
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    let mut out: String = line.chars().take(160).collect();
    if line.chars().count() > 160 {
        out.push('…');
    }
    out
}

fn log_warning(tx: &BgTx, text: String) {
    let _ = tx.send(BgEvent::Log(LogLine {
        time: now_hms(),
        level: Level::Warning,
        text,
    }));
}

/// Replaces the core: stops the old one, makes sure its TUN adapter is gone, starts the new one.
/// In this order and always through here: a changed rule or server, a reconnect and a first
/// start all take this path. A core killed outright leaves its adapter behind on Windows, and
/// starting before it is gone fails with "file already exists".
async fn start_after_stop<T, F, Fut>(
    stop: impl std::future::Future<Output = ()>,
    tun_name: Option<&str>,
    host: &dyn TunHost,
    (wait, poll): (Duration, Duration),
    log: impl Fn(String),
    mut start: F,
) -> Result<T, Failure>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, Failure>>,
{
    stop.await;
    if let Some(name) = tun_name {
        match tun::free_adapter(host, name, wait, poll).await {
            Ok(0) => {}
            Ok(n) => log(format!("removed {n} leftover TUN adapter(s) named {name}")),
            Err(e) => log(format!("could not clean up the TUN adapter {name}: {e}")),
        }
    }
    let first = start().await;
    let Some(name) = tun_name.filter(|_| host.adapter_lifecycle_managed()) else {
        return first;
    };
    match first {
        // The previous adapter is still in the way: one clean-up, one more try.
        Err(f) if tun::looks_like_adapter_exists(&f.message) => {
            log(format!(
                "the TUN adapter {name} is in the way ({}), cleaning up",
                f.message
            ));
            if let Err(e) = tun::free_adapter(host, name, wait, poll).await {
                log(format!("could not clean up the TUN adapter {name}: {e}"));
            }
            match start().await {
                Err(again) if tun::looks_like_adapter_exists(&again.message) => Err(Failure {
                    message: crate::t!("eng.tun_adapter_stuck", raw = again.message),
                    needs_privileges: false,
                    local_block: false,
                    tun_failed: true,
                }),
                other => other,
            }
        }
        other => other,
    }
}

/// What `start_core` needs.
struct StartRequest<'a> {
    server: &'a Server,
    mode: Mode,
    setup: Option<tun::Setup>,
    core_cfg: &'a CoreConfig,
    config: &'a Config,
    host: &'a dyn TunHost,
    run_dir: &'a Path,
    tx: &'a BgTx,
    store: Option<&'a StateStore>,
    checker: &'a Checker,
    backup: Option<Server>,
    known_hosts: Vec<String>,
}

/// Everything that happens between "connect" and "the core is listening", off the UI thread.
async fn start_core(request: StartRequest<'_>) -> Result<Core, Failure> {
    let StartRequest {
        server,
        mode,
        setup,
        core_cfg,
        config,
        host,
        run_dir,
        tx,
        store,
        checker,
        backup,
        known_hosts,
    } = request;
    // The API of this core has an address of its own, chosen now: a private socket (Linux) or a
    // random local port, never a fixed one.
    let mut core_with_api = core_cfg.clone();
    if core_with_api.api_port != 0 {
        let endpoint = crate::xray::api_endpoint::ApiEndpoint::choose(run_dir);
        endpoint.clear_stale();
        core_with_api.api_endpoint = Some(endpoint);
    }
    let core_cfg = &core_with_api;
    // The server must answer over TCP before anything else: afterwards, with the tunnel up,
    // this machine's own connections would go through the tunnel. The address is resolved
    // here too, so Xray never has to resolve it through the tunnel.
    let ip = tun::resolve_server(&server.address, server.port).await?;
    tun::tcp_reachable(ip, server.port, Duration::from_secs(4))
        .await
        .map_err(|e| Failure {
            // A local block already says what happened: "the server is unreachable" would not.
            message: if e.local_block {
                e.text
            } else {
                crate::t!("eng.server_tcp_down", error = e.text)
            },
            needs_privileges: false,
            local_block: e.local_block,
            tun_failed: false,
        })?;

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
    let mut core = Core::start_with(core_cfg, &cfg, run_dir, tx.clone(), &opts)
        .await
        .map_err(|e| {
            let text = e.to_string();
            let (needs_privileges, tun_failed) = classify_start_error(mode, &text);
            Failure {
                needs_privileges,
                tun_failed,
                message: text,
                local_block: false,
            }
        })?;
    if let (Some(store), Some(setup)) = (store, &setup) {
        if let Some(pid) = core.pid() {
            tun::mark_up(store, pid, &setup.interface);
        }
    }
    // The rules of this core can be changed later without a restart (see `Engine::rules_changed`).
    core.live = Some(crate::xray::routing_api::Live {
        server: server.clone(),
        plan,
        core_cfg: core_cfg.clone(),
        binary,
        config: cfg,
    });
    Ok(core)
}

impl Engine {
    /// The user's request to connect (a command, a toggled mode, an answered question): runs
    /// in the chosen mode, and an earlier TUN fallback is forgotten.
    pub(super) fn connect(&mut self, id: u64) {
        if self.busy {
            self.status(crate::t!("eng.wait_core"));
            return;
        }
        self.tun_fallback = None;
        self.connect_in(id, self.mode);
    }

    /// Starts the core for a server in the given mode. TUN that could not start comes back
    /// here in PROXY mode (see `on_core_failed`).
    fn connect_in(&mut self, id: u64, mode: Mode) {
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
                    crate::platform::IS_WINDOWS,
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

        self.restart_hint = mode == Mode::Tun && matches!(self.conn, Conn::Connected(_));
        self.traffic = Traffic::default();
        self.process_unresolved = 0;
        self.health = HealthState::Unknown;
        self.hub.clear_failure();
        self.conn = Conn::Connecting(id);
        self.conn_mode = mode;
        let old = self.take_core();
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
        let tun_name = (mode == Mode::Tun).then(|| self.config.tun.name.clone());
        if let Some(b) = &backup {
            self.logt(Level::Info, || crate::t!("eng.backup_log", name = b.name));
        }
        self.spawn(async move {
            let stop = async {
                if let Some(old) = old {
                    old.stop().await;
                    if let Some(store) = &store {
                        tun::mark_down(store);
                    }
                }
            };
            let result = start_after_stop(
                stop,
                tun_name.as_deref(),
                host.as_ref(),
                (tun::ADAPTER_WAIT, tun::ADAPTER_POLL),
                |text| log_warning(&tx, text),
                || {
                    start_core(StartRequest {
                        server: &server,
                        mode,
                        setup: setup.clone(),
                        core_cfg: &core_cfg,
                        config: &config,
                        host: host.as_ref(),
                        run_dir: &run_dir,
                        tx: &tx,
                        store: store.as_ref(),
                        checker: &checker,
                        backup: backup.clone(),
                        known_hosts: known_hosts.clone(),
                    })
                },
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
                    local_block: f.local_block,
                    tun_failed: f.tun_failed,
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
        let old = self.take_core();
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
        self.spawn(async move {
            core.stop().await;
            if let Some(store) = &store {
                tun::mark_down(store);
            }
            let _ = tx.send(BgEvent::CoreStopped);
        });
    }

    pub(super) fn on_core_started(&mut self, id: u64, mut core: Core) {
        let pid = core.pid().map(|p| p.to_string()).unwrap_or_default();
        self.live = core.live.take();
        self.core = Some(core);
        self.conn = Conn::Connected(id);
        self.tun_active = self.conn_mode == Mode::Tun;
        self.sync_proxy();
        if std::mem::take(&mut self.restart_hint) && self.conn_mode == Mode::Tun {
            self.status(crate::t!("eng.restart_apps"));
        }
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

    pub(super) fn on_core_failed(
        &mut self,
        id: u64,
        error: String,
        needs_privileges: bool,
        local_block: bool,
        tun_failed: bool,
    ) {
        self.log(Level::Error, format!("[Error] {error}"));
        if self.conn != Conn::Connecting(id) {
            return;
        }
        if tun_failed && self.conn_mode == Mode::Tun {
            // TUN did not come up: do not leave the user without a VPN. The same start path
            // again, without the TUN inbound; the system proxy goes on whatever the settings say.
            let reason = short_reason(&error);
            self.tun_active = false;
            self.tun_fallback = Some(reason.clone());
            self.restart_hint = false;
            self.alert(Alert::Notice(crate::t!(
                "eng.tun_fallback",
                reason = reason
            )));
            self.connect_in(id, Mode::Proxy);
            return;
        }
        self.tun_fallback = None;
        self.tun_active = false;
        self.conn = Conn::Error(crate::t!("eng.core_start_failed"));
        self.request_proxy_off();
        if needs_privileges {
            self.show_problem(&Problem::NeedsPrivileges);
        } else if local_block && crate::platform::IS_WINDOWS {
            // The button: one elevated run that sets the firewall right, then it ends.
            self.failure_alert(Alert::Ask {
                text: crate::t!("eng.firewall_ask", error = error),
                ask: Ask::ConfigureFirewall,
            });
        } else {
            self.failure_alert(Alert::Failure(error));
        }
    }

    // ---------- the connection check ----------

    fn spawn_health(&mut self, id: u64) {
        self.health = HealthState::Checking;
        let tx = self.tx.clone();
        let socks_port = self.config.core.socks_port;
        let tun = (self.conn_mode == Mode::Tun).then(|| {
            let dns = &self.config.tun.tunnel_dns;
            // The adapter's own resolver is a plain address; a URL setting falls back to 1.1.1.1.
            let dns = if dns.parse::<std::net::IpAddr>().is_ok() {
                dns.clone()
            } else {
                "1.1.1.1".to_string()
            };
            (self.tun_host.clone(), self.config.tun.name.clone(), dns)
        });
        self.spawn(async move {
            let in_tun = tun.is_some();
            if let Some((host, name, dns)) = tun {
                // The adapter appears a moment after the core starts.
                for _ in 0..10 {
                    let (h, n, d) = (host.clone(), name.clone(), dns.clone());
                    let done =
                        tokio::task::spawn_blocking(move || h.prefer_tun_adapter_dns(&n, &d))
                            .await
                            .map(|r| r.is_ok())
                            .unwrap_or(false);
                    if done || !crate::platform::IS_WINDOWS {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
            // The first request right after the start can race with the routes settling.
            let mut last = HealthError::NoAnswer { secs: 0 };
            for attempt in 0..2 {
                match health::check(socks_port, health::HEALTH_TIMEOUT).await {
                    Ok(latency) => {
                        // The tunnel works; names must resolve through the system path too.
                        let result = if in_tun && !health::system_dns_resolves().await {
                            Err(HealthError::DnsBypass)
                        } else {
                            Ok(latency)
                        };
                        let _ = tx.send(BgEvent::Health { id, result });
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

    pub(super) fn on_health(&mut self, id: u64, result: Result<Duration, HealthError>) {
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
                self.health = HealthState::Failed(e.to_string());
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
        match problem {
            Problem::NeedsPrivileges if crate::platform::IS_WINDOWS => {
                self.failure_alert(Alert::Ask {
                    text,
                    ask: Ask::RelaunchElevated,
                })
            }
            p if p.is_blocking() => self.failure_alert(Alert::Failure(text)),
            _ => self.alert(Alert::Notice(text)),
        }
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
    use crate::test_support::TempDir;
    use tokio::sync::mpsc::unbounded_channel;

    /// An app in TUN mode with one real server and a scripted host. The TUN core path points at
    /// a file that exists unless `core_exists` is false.
    fn tun_app(host: MockTunHost, core_exists: bool, dir: &Path) -> (Engine, u64) {
        let mut config = crate::test_support::config_ru();
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
        let dir = TempDir::new("offer");
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
        let dir = TempDir::new("accept");
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
            matches!(a.alerts().last(), Some(Alert::Failure(_))),
            "the missing core is reported: {:?}",
            a.alerts()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn declining_the_offer_keeps_everything_through_the_vpn() {
        let dir = TempDir::new("decline");
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
        let dir = TempDir::new("once");
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
        let dir = TempDir::new("blocking");
        let cases: Vec<(MockTunHost, bool, &str)> = vec![
            (
                MockTunHost::healthy(),
                false,
                if crate::platform::IS_WINDOWS {
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
                Some(Alert::Failure(t)) => t.clone(),
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
        let dir = TempDir::new("privileges");
        let host = MockTunHost {
            can_create_tun: Some(false),
            ..MockTunHost::healthy()
        };
        let (mut a, id) = tun_app(host, true, &dir);
        a.config.ui.tun_intro_done = true;
        a.connect(id);
        if crate::platform::IS_WINDOWS {
            assert!(matches!(
                a.alerts().last(),
                Some(Alert::Ask {
                    ask: Ask::RelaunchElevated,
                    ..
                })
            ));
        } else {
            let Some(Alert::Failure(text)) = a.alerts().last().cloned() else {
                panic!("{:?}", a.alerts())
            };
            assert!(
                text.contains("sudo setcap") && text.contains("sudo elf-gate"),
                "{text}"
            );
        }
        // Nothing was started: the check is ours, Xray never ran.
        assert!(!a.busy, "no start task");
        assert!(a.core.is_none(), "no core");
        assert_ne!(a.conn, Conn::Connecting(id));
        // The server is remembered so an elevated restart can reconnect to it.
        assert_eq!(a.config.ui.last_server.as_deref(), Some("manual/Real"));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// 10013 at the connect check: the server is not blamed, and where there is a firewall to
    /// set up the dialog offers it.
    #[tokio::test]
    async fn a_local_block_offers_the_firewall_and_leaves_the_server_alone() {
        let (tx, _rx) = unbounded_channel();
        let mut a = Engine::build(tx, crate::test_support::config_ru(), None, false);
        a.add_link("vless://u@10.0.0.5:443?security=none#Real".into());
        let id = a.subs.last().unwrap().servers[0].id;
        a.conn = Conn::Connecting(id);
        a.on_core_failed(
            id,
            "Windows запретила elf-gate подключиться".into(),
            false,
            true,
            false,
        );
        let last = a.alerts().last().cloned();
        if crate::platform::IS_WINDOWS {
            let Some(Alert::Ask { text, ask }) = last else {
                panic!("{:?}", a.alerts())
            };
            assert_eq!(ask, Ask::ConfigureFirewall);
            assert!(text.contains("Windows запретила"), "{text}");
        } else {
            assert!(matches!(last, Some(Alert::Failure(_))), "{last:?}");
        }
        let server = &a.subs.last().unwrap().servers[0];
        assert!(server.unsupported.is_none(), "the server is not marked");
        assert_eq!(server.ping, crate::model::server::Ping::Unknown);

        a.handle_cmd(Cmd::Answer {
            ask: Ask::ConfigureFirewall,
            yes: false,
        });
        assert!(!a.firewall_setup_requested);
        a.handle_cmd(Cmd::Answer {
            ask: Ask::ConfigureFirewall,
            yes: true,
        });
        assert!(
            a.firewall_setup_requested,
            "the loop starts the elevated run"
        );
    }

    #[tokio::test]
    async fn declining_elevation_explains_that_tun_needs_it() {
        let (tx, _rx) = unbounded_channel();
        let mut a = Engine::build(tx, crate::test_support::config_ru(), None, false);
        a.handle_cmd(Cmd::Answer {
            ask: Ask::RelaunchElevated,
            yes: false,
        });
        assert!(a.last_status().unwrap().contains("администратора"));
    }

    #[tokio::test]
    async fn a_start_error_about_permissions_becomes_the_privileges_dialog() {
        let (tx, _rx) = unbounded_channel();
        let mut a = Engine::build(tx, crate::test_support::config_ru(), None, false);
        a.add_link("vless://u@10.0.0.5:443?security=none#Real".into());
        let id = a.subs[0].servers[0].id;
        a.conn = Conn::Connecting(id);
        a.on_core_failed(
            id,
            "ядро завершилось сразу (operation not permitted)".into(),
            true,
            false,
            false,
        );
        assert!(matches!(a.conn, Conn::Error(_)));
        assert!(!a.alerts().is_empty());
        // An ordinary failure shows the error text itself.
        a.conn = Conn::Connecting(id);
        a.on_core_failed(
            id,
            "порт 10808 (socks) уже занят другой программой".into(),
            false,
            false,
            false,
        );
        assert!(matches!(a.alerts().last(), Some(Alert::Failure(t)) if t.contains("10808")));
    }

    #[tokio::test]
    async fn strict_rp_filter_is_a_notice_and_does_not_stop_the_start() {
        let dir = TempDir::new("rp");
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
        let mut a = Engine::build(tx, crate::test_support::config_ru(), None, false);
        a.add_link("vless://u@h.example.com:443?security=none#R".into());
        let id = a.subs[0].servers[0].id;
        a.conn = Conn::Connected(id);
        a.on_health(id, Ok(Duration::from_millis(80)));
        assert_eq!(a.health, HealthState::Ok(Duration::from_millis(80)));
        a.on_health(id, Err(HealthError::NoAnswer { secs: 8 }));
        assert!(matches!(a.health, HealthState::Failed(_)));
        a.conn = Conn::Disconnected;
        a.health = HealthState::Unknown;
        a.on_health(id, Err(HealthError::BadSocks));
        assert_eq!(a.health, HealthState::Unknown);
    }

    /// Texts made by a task on a worker thread follow the engine's language (here Ukrainian:
    /// neither the process default nor the Russian of most tests).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn texts_made_in_tasks_follow_the_engine_language() {
        use crate::i18n::Lang;
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let (tx, mut rx) = unbounded_channel();
        let mut config = crate::test_support::config_ru();
        config.ui.language = Lang::Uk;
        let mut a = Engine::build(tx, config, None, false);
        a.add_link(format!("vless://u@127.0.0.1:{closed}?security=none#Dead"));
        let id = a.subs[0].servers[0].id;
        a.connect(id);
        let error = loop {
            let event = tokio::time::timeout(Duration::from_secs(20), rx.recv())
                .await
                .expect("no event")
                .expect("channel closed");
            if let BgEvent::CoreFailed { error, .. } = event {
                break error;
            }
        };
        let (uk, en) = (
            crate::i18n::with_lang(Lang::Uk, || crate::t!("eng.server_tcp_down", error = "")),
            crate::i18n::with_lang(Lang::En, || crate::t!("eng.server_tcp_down", error = "")),
        );
        assert_ne!(uk, en);
        assert!(
            error.starts_with(uk.trim_end_matches([' ', ':'])),
            "{error}"
        );
    }

    fn tiny() -> (Duration, Duration) {
        (Duration::from_millis(200), Duration::from_millis(2))
    }

    /// stop, then the wait for the adapter, then the start; never a start before the adapter
    /// is gone.
    #[tokio::test]
    async fn the_new_core_starts_after_the_old_one_stopped_and_its_adapter_is_gone() {
        use std::sync::Mutex;
        let log: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let host = MockTunHost {
            managed_adapter: true,
            present_polls: Mutex::new(3),
            ..MockTunHost::healthy()
        };
        let r: Result<u8, Failure> = start_after_stop(
            async { log.lock().unwrap().push("stop".into()) },
            Some("elfgate0"),
            &host,
            tiny(),
            |t| log.lock().unwrap().push(format!("log: {t}")),
            || async {
                // The adapter is gone by now: the scripted polls ran out.
                assert_eq!(*host.present_polls.lock().unwrap(), 0);
                log.lock().unwrap().push("start".into());
                Ok(1)
            },
        )
        .await;
        assert_eq!(r.unwrap(), 1);
        assert_eq!(*log.lock().unwrap(), ["stop", "start"]);
        // Nothing left: the cleanup ran (it also looks for ghosts) and found nothing.
        assert_eq!(*host.removed_names.lock().unwrap(), ["elfgate0"]);
    }

    #[tokio::test]
    async fn an_adapter_that_stays_or_a_ghost_is_removed_before_the_start() {
        use std::sync::Mutex;
        let log: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let host = MockTunHost {
            managed_adapter: true,
            present_polls: Mutex::new(u32::MAX),
            stale_devices: Mutex::new(1),
            ..MockTunHost::healthy()
        };
        let r: Result<u8, Failure> = start_after_stop(
            async { log.lock().unwrap().push("stop".into()) },
            Some("elfgate0"),
            &host,
            tiny(),
            |t| log.lock().unwrap().push(format!("log: {t}")),
            || async {
                log.lock().unwrap().push("start".into());
                Ok(1)
            },
        )
        .await;
        assert!(r.is_ok());
        let log = log.lock().unwrap();
        assert_eq!(log[0], "stop");
        assert!(
            log[1].contains("removed 1 leftover") && log[1].contains("elfgate0"),
            "{log:?}"
        );
        assert_eq!(log[2], "start");
        assert_eq!(*host.removed_names.lock().unwrap(), ["elfgate0"]);
    }

    fn failure(text: &str) -> Failure {
        Failure {
            message: text.into(),
            needs_privileges: false,
            local_block: false,
            tun_failed: true,
        }
    }

    const EXISTS: &str = "Failed to setup adapter (problem code: 0x1F, ntstatus: 0xC0000035): Cannot create a file when that file already exists. (Code 0x000000B7)";

    /// One clean-up and one more try; the second try works.
    #[tokio::test]
    async fn the_adapter_error_gets_one_cleanup_and_a_second_try() {
        use std::sync::Mutex;
        let log: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let host = MockTunHost {
            managed_adapter: true,
            stale_devices: Mutex::new(1),
            ..MockTunHost::healthy()
        };
        let mut tries = 0;
        let r: Result<u8, Failure> = start_after_stop(
            async {},
            Some("elfgate0"),
            &host,
            tiny(),
            |t| log.lock().unwrap().push(t),
            || {
                tries += 1;
                let n = tries;
                async move {
                    if n == 1 {
                        Err(failure(EXISTS))
                    } else {
                        Ok(7)
                    }
                }
            },
        )
        .await;
        assert_eq!(r.unwrap(), 7);
        assert_eq!(tries, 2);
        // Cleaned up before the first start and again after its failure.
        assert_eq!(host.removed_names.lock().unwrap().len(), 2);
        assert!(log.lock().unwrap().iter().any(|l| l.contains("in the way")));
    }

    /// Still failing: the user gets the advice and the raw log, and there is no third try.
    #[tokio::test]
    async fn a_second_failure_gives_the_advice_with_the_raw_log_under_it() {
        let host = MockTunHost {
            managed_adapter: true,
            ..MockTunHost::healthy()
        };
        let mut tries = 0;
        let r: Result<u8, Failure> = crate::i18n::scoped(
            crate::i18n::Lang::Ru,
            start_after_stop(
                async {},
                Some("elfgate0"),
                &host,
                tiny(),
                |_| {},
                || {
                    tries += 1;
                    async { Err(failure(EXISTS)) }
                },
            ),
        )
        .await;
        assert_eq!(tries, 2, "exactly one retry");
        let message = r.unwrap_err().message;
        let advice = message.find("езагрузите").expect("advice to restart");
        assert!(message.contains("PROXY"), "{message}");
        let raw_at = message.find(EXISTS).expect("the raw log is kept");
        assert!(raw_at > advice, "the advice comes first, the log under it");
    }

    /// Other errors are not retried, and Linux never retries.
    #[tokio::test]
    async fn other_errors_and_unmanaged_hosts_are_not_retried() {
        for (managed, text) in [(true, "port busy"), (false, EXISTS)] {
            let host = MockTunHost {
                managed_adapter: managed,
                ..MockTunHost::healthy()
            };
            let mut tries = 0;
            let r: Result<u8, Failure> = start_after_stop(
                async {},
                Some("elfgate0"),
                &host,
                tiny(),
                |_| {},
                || {
                    tries += 1;
                    async move { Err(failure(text)) }
                },
            )
            .await;
            assert_eq!(tries, 1, "{text} managed={managed}");
            assert_eq!(r.unwrap_err().message, text);
        }
    }

    /// Linux and the proxy mode: nothing is waited for, nothing is removed.
    #[tokio::test]
    async fn without_a_managed_adapter_or_in_proxy_mode_nothing_is_waited_for() {
        use std::sync::Mutex;
        let host = MockTunHost {
            present_polls: Mutex::new(1000),
            ..MockTunHost::healthy()
        };
        let start = std::time::Instant::now();
        for name in [Some("elfgate0"), None] {
            let r: Result<u8, Failure> =
                start_after_stop(async {}, name, &host, tiny(), |_| {}, || async { Ok(1) }).await;
            assert!(r.is_ok());
        }
        assert!(start.elapsed() < Duration::from_millis(150));
        assert!(host.removed_names.lock().unwrap().is_empty());
        assert_eq!(*host.present_polls.lock().unwrap(), 1000, "never asked");
    }

    /// A rule change confirmed with "apply" restarts the core through the same path as a
    /// first connect: the adapter clean-up runs before the new core is started.
    #[tokio::test]
    async fn applying_changed_rules_restarts_through_the_adapter_cleanup() {
        let dir = TempDir::new("apply");
        let host = Arc::new(MockTunHost {
            managed_adapter: true,
            ..MockTunHost::healthy()
        });
        let (mut a, id) = tun_app(MockTunHost::healthy(), true, &dir);
        a.tun_host = host.clone();
        a.config.ui.tun_intro_done = true;
        a.handle_cmd(Cmd::Answer {
            ask: crate::proto::Ask::ApplyRules(id),
            yes: true,
        });
        assert!(a.busy, "a start is under way");
        let end = std::time::Instant::now() + Duration::from_secs(5);
        while host.removed_names.lock().unwrap().is_empty() {
            assert!(std::time::Instant::now() < end, "the clean-up never ran");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            *host.removed_names.lock().unwrap(),
            [a.config.tun.name.clone()]
        );
    }

    #[tokio::test]
    async fn tun_toggle_switches_mode_and_remembers_it() {
        let dir = TempDir::new("toggle");
        let storage = Storage::new(dir.path());
        let (tx, _rx) = unbounded_channel();
        let mut a = Engine::build(
            tx,
            crate::test_support::config_ru(),
            Some(storage.clone()),
            false,
        );
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
        let dir = TempDir::new("cli");
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
        assert!(matches!(a.alerts().last(), Some(Alert::Failure(_))));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn the_hub_keeps_the_last_failure_for_a_later_interface_until_it_is_answered() {
        let dir = TempDir::new("failure-kept");
        let (mut a, _id) = tun_app(MockTunHost::healthy(), false, &dir);
        a.config.ui.auto_connect = true;
        a.config.mode.traffic = Mode::Tun;
        a.config.ui.last_server = Some("manual/Real".into());
        a.config.ui.tun_intro_done = true;
        assert!(a.hub().subscribe().failure.is_none());

        // Nobody is subscribed while the start fails (autostart): the broadcast is lost.
        a.auto_connect();
        let kept = a.hub().subscribe().failure;
        assert!(matches!(kept, Some(Alert::Failure(_))), "{kept:?}");
        assert_eq!(
            a.hub().subscribe().failure,
            kept,
            "reading does not consume it"
        );

        a.answer(Ask::RelaunchElevated, false);
        assert!(a.hub().subscribe().failure.is_none(), "answered: gone");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_new_connection_attempt_clears_the_kept_failure() {
        let dir = TempDir::new("failure-cleared");
        let (mut a, id) = tun_app(MockTunHost::healthy(), false, &dir);
        a.hub().fail(Alert::Error("old".into()));
        a.mode = Mode::Proxy;
        a.connect(id);
        assert!(a.hub().subscribe().failure.is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn auto_connect_is_off_by_default_and_uses_the_last_mode_when_on() {
        let dir = TempDir::new("auto");
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
        assert!(matches!(a.alerts().last(), Some(Alert::Failure(_))));
        assert_eq!(a.server_by_id(id).unwrap().name, "Real");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn startup_cleans_up_a_core_left_by_a_crash() {
        let dir = TempDir::new("cleanup");
        let store = StateStore::new(dir.path());
        tun::mark_up(&store, 777, "elfgate0");
        let host = Arc::new(MockTunHost::healthy());
        let (tx, _rx) = unbounded_channel();
        let mut a = Engine::build(tx, crate::test_support::config_ru(), None, false)
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
        let dir = TempDir::new("caps");
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
        let mut a = Engine::build(tx, crate::test_support::config_ru(), None, false);
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

    // ---------- mixed mode: TUN + system proxy, and the fall back to the proxy ----------

    #[test]
    fn only_a_real_tun_problem_counts_as_a_tun_failure() {
        assert_eq!(
            classify_start_error(Mode::Tun, "Failed to create wintun adapter"),
            (false, true)
        );
        assert_eq!(
            classify_start_error(Mode::Tun, "operation not permitted"),
            (true, false),
            "no rights: the privileges dialog, not a fall back"
        );
        assert_eq!(
            classify_start_error(Mode::Proxy, "address already in use"),
            (false, false)
        );
    }

    #[tokio::test]
    async fn the_proxy_follows_the_settings_in_both_modes_and_is_forced_after_a_fall_back() {
        let dir = TempDir::new("wanted");
        let (mut a, _) = tun_app(MockTunHost::healthy(), true, &dir);
        for (conn_mode, set, with_tun, want) in [
            (Mode::Proxy, true, true, true),
            (Mode::Proxy, true, false, true),
            (Mode::Proxy, false, true, false),
            (Mode::Tun, true, true, true),
            (Mode::Tun, true, false, false),
            (Mode::Tun, false, true, false),
        ] {
            a.conn_mode = conn_mode;
            a.config.proxy.set_system_proxy = set;
            a.config.proxy.with_tun = with_tun;
            assert_eq!(
                a.proxy_wanted(),
                want,
                "{conn_mode:?} set={set} with_tun={with_tun}"
            );
        }
        a.tun_fallback = Some("x".into());
        a.conn_mode = Mode::Proxy;
        a.config.proxy.set_system_proxy = false;
        a.config.proxy.with_tun = false;
        assert!(a.proxy_wanted(), "the proxy is the only way in now");
    }

    #[test]
    fn the_default_setting_is_mixed_mode() {
        assert!(crate::storage::Config::default().proxy.with_tun);
    }

    #[tokio::test]
    async fn a_tun_that_does_not_start_restarts_the_core_as_a_proxy_and_says_so() {
        let dir = TempDir::new("fallback");
        let (mut a, id) = tun_app(MockTunHost::healthy(), true, &dir);
        a.conn = Conn::Connecting(id);
        a.conn_mode = Mode::Tun;
        a.config.proxy.with_tun = false;
        a.on_core_failed(
            id,
            "Failed to create wintun adapter\nsecond line".into(),
            false,
            false,
            true,
        );
        assert_eq!(a.conn, Conn::Connecting(id), "a new start is under way");
        assert_eq!(a.conn_mode, Mode::Proxy, "without the TUN inbound");
        assert!(!a.tun_active);
        assert_eq!(
            a.tun_fallback.as_deref(),
            Some("Failed to create wintun adapter")
        );
        assert!(a.proxy_wanted(), "even with the setting off");
        let last = a.alerts().last().cloned();
        let Some(Alert::Notice(text)) = last else {
            panic!("{:?}", a.alerts())
        };
        assert!(
            text.contains("wintun adapter") && text.contains("Discord"),
            "{text}"
        );
        assert_eq!(a.view().tun_fallback, a.tun_fallback);
    }

    #[tokio::test]
    async fn refusing_the_rights_is_not_a_tun_failure() {
        let dir = TempDir::new("noroll");
        let (mut a, id) = tun_app(MockTunHost::healthy(), true, &dir);
        a.conn = Conn::Connecting(id);
        a.conn_mode = Mode::Tun;
        a.on_core_failed(id, "operation not permitted".into(), true, false, false);
        assert!(a.tun_fallback.is_none());
        assert!(matches!(a.conn, Conn::Error(_)), "{:?}", a.conn);
        assert!(!a.alerts().is_empty(), "the rights dialog is shown");
        assert!(a
            .alerts()
            .iter()
            .all(|l| !matches!(l, Alert::Notice(t) if t.contains("Discord"))));
    }

    #[tokio::test]
    async fn a_user_connect_forgets_an_earlier_fall_back() {
        let dir = TempDir::new("forget");
        let (mut a, id) = tun_app(MockTunHost::healthy(), true, &dir);
        a.tun_fallback = Some("x".into());
        a.mode = Mode::Proxy;
        a.connect(id);
        assert!(a.tun_fallback.is_none());
    }

    /// The system proxy set next to TUN is put back on exit, like in plain PROXY mode.
    #[tokio::test]
    async fn the_proxy_set_next_to_tun_is_restored_on_exit() {
        use crate::platform::mock::{MockProxy, SharedMock};
        let dir = TempDir::new("mixed-exit");
        let mock = Arc::new(MockProxy::with_user_settings(&[("enabled", "0")]));
        let before = mock.snapshot();
        let controller = Arc::new(crate::sysproxy::ProxyController::new(
            Box::new(SharedMock(mock.clone())),
            StateStore::new(dir.path()),
        ));
        let (tx, _rx) = unbounded_channel();
        let handle = crate::sysproxy::ProxyHandle::spawn(controller, tx.clone());
        let (a, id) = tun_app(MockTunHost::healthy(), true, dir.path());
        let mut a = a.with_proxy(handle);
        a.conn = Conn::Connected(id);
        a.conn_mode = Mode::Tun;
        a.tun_active = true;
        a.sync_proxy();
        for _ in 0..100 {
            if mock.snapshot().values.get("enabled").map(String::as_str) == Some("1") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(mock.snapshot().values["enabled"], "1", "on in TUN mode");
        assert_eq!(mock.snapshot().values["server"], "127.0.0.1:10809");
        a.shutdown().await;
        assert_eq!(mock.snapshot(), before, "the user's settings are back");
    }

    #[tokio::test]
    async fn with_tun_off_the_proxy_stays_untouched_next_to_tun() {
        use crate::platform::mock::{MockProxy, SharedMock};
        let dir = TempDir::new("tun-only");
        let mock = Arc::new(MockProxy::with_user_settings(&[("enabled", "0")]));
        let before = mock.snapshot();
        let controller = Arc::new(crate::sysproxy::ProxyController::new(
            Box::new(SharedMock(mock.clone())),
            StateStore::new(dir.path()),
        ));
        let (tx, _rx) = unbounded_channel();
        let handle = crate::sysproxy::ProxyHandle::spawn(controller, tx);
        let (a, id) = tun_app(MockTunHost::healthy(), true, dir.path());
        let mut a = a.with_proxy(handle);
        a.config.proxy.with_tun = false;
        a.conn = Conn::Connected(id);
        a.conn_mode = Mode::Tun;
        a.sync_proxy();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(mock.snapshot(), before);
    }

    /// A restart in TUN mode while connected (new rules, preset or server) tells the user that
    /// programs which are already connected keep their old route.
    #[tokio::test]
    async fn a_restart_in_tun_mode_hints_to_restart_the_programs() {
        let dir = TempDir::new("hint");
        let (mut a, id) = tun_app(MockTunHost::healthy(), true, &dir);
        a.config.ui.tun_intro_done = true;
        a.conn = Conn::Connected(id);
        a.connect(id);
        assert!(a.restart_hint, "set by a restart that was Connected");
        a.restart_hint = false;
        a.busy = false;
        a.conn = Conn::Disconnected;
        a.connect(id);
        assert!(!a.restart_hint, "a first connect needs no hint");
    }
}
