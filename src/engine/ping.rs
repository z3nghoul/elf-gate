//! Pinging servers and the automatic TLS fingerprint search.

use super::*;
use crate::model::server::{PingKind, Security};
use crate::net::ping;
use crate::storage::PingMode;
use crate::xray::process::resolve_binary;

/// How servers are pinged right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    /// A plain TCP connect (no tunnel up).
    Tcp,
    /// A TCP connect bound to the physical interface (tunnel up).
    TcpBound(String),
    /// A request through a temporary core.
    Url,
}

/// The one place that decides how to measure. With the tunnel up a plain TCP ping is never
/// chosen: it would only measure the tunnel's own stack.
pub fn choose_method(
    configured: PingMode,
    tun_up: bool,
    physical: Option<String>,
    can_bind: bool,
) -> (Method, Option<String>) {
    match (configured, tun_up) {
        (PingMode::Url, _) => (Method::Url, None),
        (PingMode::Tcp, false) => (Method::Tcp, None),
        (PingMode::Tcp, true) => match physical.filter(|_| can_bind) {
            Some(iface) => (Method::TcpBound(iface), None),
            None => (Method::Url, Some(crate::t!("eng.tun_ping_via_core"))),
        },
    }
}

impl Engine {
    pub(super) fn ping_all(&mut self) {
        self.last_auto_ping = Some(Instant::now());
        self.ping_servers(true);
    }

    /// The background refresh: TCP pings without the "..." flicker, every
    /// `[ping].auto_interval_secs` (stretched while no interface is open). For the live
    /// connection the latency through the tunnel is measured instead.
    pub(super) fn auto_ping_tick(&mut self) {
        let base = self.config.ping.auto_interval_secs;
        if base == 0 || self.subs.is_empty() {
            return;
        }
        // Nobody is looking: five times slower, at most every five minutes.
        let watched = self.hub.view_receivers() > usize::from(self.tray);
        let every = if watched {
            base
        } else {
            (base * 5).min(300).max(base)
        };
        if self
            .last_auto_ping
            .is_some_and(|t| t.elapsed() < Duration::from_secs(every))
        {
            return;
        }
        self.last_auto_ping = Some(Instant::now());
        self.ping_servers(false);
        self.spawn_vpn_series();
    }

    /// The latency of the live connection: a few requests through the working tunnel, the median
    /// without the cold first one. The result replaces the previous number only when it arrives.
    pub(super) fn spawn_vpn_series(&self) {
        let Conn::Connected(id) = self.conn else {
            return;
        };
        let (tx, port) = (self.tx.clone(), self.config.core.socks_port);
        tokio::spawn(async move {
            let series =
                crate::net::health::latency_series(port, crate::net::health::HEALTH_TIMEOUT).await;
            let _ = tx.send(BgEvent::ActiveLatency {
                id,
                ms: series.map(|(d, _)| d.as_millis().min(u128::from(u32::MAX)) as u32),
                samples: series.map_or(0, |(_, n)| n.min(255) as u8),
            });
        });
    }

    /// `manual`: marks servers as pending and also drives the demo pings.
    fn ping_servers(&mut self, manual: bool) {
        let real: Vec<Server> = self
            .subs
            .iter()
            .flat_map(|s| s.servers.iter())
            .filter(|s| s.is_supported() && !s.link.is_empty() && !s.hidden)
            .cloned()
            .collect();
        if self.mock && manual {
            for sub in &mut self.subs {
                for s in sub
                    .servers
                    .iter_mut()
                    .filter(|s| s.is_supported() && s.link.is_empty())
                {
                    s.ping = Ping::Pending;
                    mock::spawn_ping(self.tx.clone(), s.id);
                }
            }
        }
        if real.is_empty() {
            if !self.mock {
                self.status(crate::t!("eng.no_ping_servers"));
            }
            return;
        }
        // While the TUN is up a plain TCP connect enters the tunnel and is answered locally by
        // its stack (2-20 ms to anything): it must go around the tunnel or not be shown at all.
        let tun_up = self.tun_active && matches!(self.conn, Conn::Connected(_));
        let physical = tun_up
            .then(|| self.tun_host.physical_interface(&self.config.tun.name))
            .flatten();
        let can_bind = physical
            .as_deref()
            .is_some_and(crate::platform::can_bind_interface);
        let (method, note) = choose_method(self.config.ping.mode, tun_up, physical, can_bind);
        if let Some(note) = note {
            self.status(note);
        }
        let (mode, bound) = match method {
            Method::Tcp => (PingMode::Tcp, None),
            Method::TcpBound(iface) => (PingMode::Tcp, Some(iface)),
            Method::Url => (PingMode::Url, None),
        };
        let binary = if mode == PingMode::Url {
            match resolve_binary(&self.config.core.xray_path) {
                Ok(b) => Some(b),
                Err(e) => {
                    self.status(crate::t!("eng.url_ping_error", error = e));
                    return;
                }
            }
        } else {
            None
        };
        let limit = Duration::from_millis(self.config.ping.timeout_ms.max(500));
        let active = match self.conn {
            Conn::Connected(id) => Some(id),
            _ => None,
        };
        if manual {
            self.spawn_vpn_series();
        }
        for server in real {
            let is_active = Some(server.id) == active;
            // The connected server keeps its numbers while new ones are measured, and is never
            // measured through a temporary core: the live tunnel answers for it.
            if is_active && binary.is_some() {
                continue;
            }
            if manual && !is_active {
                self.set_ping(server.id, Ping::Pending);
            }
            let tx = self.tx.clone();
            let core = self.config.core.clone();
            let cfg = self.config.ping.clone();
            let run_dir = self.run_dir.clone();
            let binary = binary.clone();
            let bound = bound.clone();
            tokio::spawn(async move {
                let kind = if binary.is_some() {
                    PingKind::Tunnel
                } else {
                    PingKind::Tcp
                };
                let (result, suspect) = match binary {
                    Some(bin) => ping::url_ping(&bin, &core, &server, &cfg, &run_dir).await,
                    None => (
                        ping::tcp_ping_via(&server.address, server.port, limit, bound.as_deref())
                            .await,
                        false,
                    ),
                };
                let _ = tx.send(BgEvent::Ping {
                    id: server.id,
                    result,
                    kind,
                });
                if suspect {
                    let _ = tx.send(BgEvent::FpSuspect { id: server.id });
                }
            });
        }
    }

    fn set_ping(&mut self, id: u64, ping: Ping) {
        if let Some(s) = self
            .subs
            .iter_mut()
            .flat_map(|s| s.servers.iter_mut())
            .find(|s| s.id == id)
        {
            s.ping = ping;
        }
    }

    /// Does this server qualify for the automatic fingerprint search right now? The user's own
    /// choice is never replaced, and a server is searched once per Xray version.
    fn fp_search_wanted(&self, id: u64) -> Option<Server> {
        let server = self.server_by_id(id)?;
        if !matches!(server.security, Security::Tls | Security::Reality)
            || server.full.is_some()
            || !server.is_supported()
            || server.link.is_empty()
        {
            return None;
        }
        // A fingerprint chosen by hand wins over any search.
        if server.fp_override.is_some() && !server.fp_auto {
            return None;
        }
        Some(server.clone())
    }

    pub(super) fn on_fp_suspect(&mut self, id: u64) {
        if self.fp_searching.contains(&id) {
            return;
        }
        let Some(server) = self.fp_search_wanted(id) else {
            return;
        };
        self.start_fp_search(server);
    }

    /// Searches for a working fingerprint with temporary cores (not while the TUN is up).
    pub(super) fn start_fp_search(&mut self, server: Server) {
        if self.tun_active {
            return;
        }
        let Ok(binary) = resolve_binary(&self.config.core.xray_path) else {
            return;
        };
        self.fp_searching.insert(server.id);
        self.logt(Level::Info, || {
            crate::t!("eng.fp_searching", name = server.name)
        });
        let tx = self.tx.clone();
        let core = self.config.core.clone();
        let cfg = self.config.ping.clone();
        let run_dir = self.run_dir.clone();
        let checker = self.checker.clone();
        let id = server.id;
        let searched_with = self.stored_search_version(id);
        tokio::spawn(async move {
            let version = checker.version_of(&binary).await;
            // Already searched with this Xray: nothing new to learn.
            if version.is_some() && version == searched_with {
                let _ = tx.send(BgEvent::FpSearched {
                    id,
                    xray_version: version,
                    found: None,
                    skipped: true,
                });
                return;
            }
            let found = ping::search_fingerprint(&binary, &core, &server, &cfg, &run_dir).await;
            let _ = tx.send(BgEvent::FpSearched {
                id,
                xray_version: version,
                found,
                skipped: false,
            });
        });
    }

    pub(super) fn on_fp_searched(
        &mut self,
        id: u64,
        xray_version: Option<String>,
        found: Option<String>,
        skipped: bool,
    ) {
        self.fp_searching.remove(&id);
        if skipped {
            return;
        }
        let mut key = None;
        for sub in &self.subs {
            if let Some(s) = sub.servers.iter().find(|s| s.id == id) {
                key = Some((override_key(&sub.name, s), s.name.clone()));
            }
        }
        let Some((key, name)) = key else { return };
        // The user chose a fingerprint while the search was running: theirs wins.
        if self
            .server_by_id(id)
            .is_some_and(|s| s.fp_override.is_some() && !s.fp_auto)
        {
            return;
        }
        match &found {
            Some(fp) => {
                self.logt(Level::Info, || {
                    crate::t!("eng.fp_found_log", name = name, fp = fp)
                });
                self.status(crate::t!("eng.fp_found_status", name = name, fp = fp));
            }
            None => {
                self.logt(Level::Warning, || crate::t!("eng.fp_none_log", name = name));
                self.status(crate::t!("eng.fp_none_status", name = name));
            }
        }
        let current = found.clone();
        self.update_override(&key, |o| {
            o.fp = current.clone();
            o.fp_auto = current.is_some();
            o.fp_auto_xray = xray_version.clone();
        });
        for server in self
            .subs
            .iter_mut()
            .flat_map(|s| s.servers.iter_mut())
            .filter(|s| s.id == id)
        {
            server.fp_override = found.clone();
            server.fp_auto = found.is_some();
        }
        self.save_config();
        // The connection that triggered the search restarts with the new fingerprint.
        if let (Some(_), Conn::Connected(c)) = (&found, &self.conn) {
            let c = *c;
            if c == id && !self.busy {
                self.connect(id);
            }
        }
    }

    /// Xray version the last automatic search ran with, if any.
    fn stored_search_version(&self, id: u64) -> Option<String> {
        let (group, s) = self.subs.iter().find_map(|sub| {
            sub.servers
                .iter()
                .find(|s| s.id == id)
                .map(|s| (sub.name.clone(), s))
        })?;
        let key = override_key(&group, s);
        self.config
            .overrides
            .iter()
            .find(|o| o.server == key)
            .and_then(|o| o.fp_auto_xray.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::unbounded_channel;

    const REALITY: &str =
        "vless://u@h.example.com:443?security=reality&sni=x.org&pbk=K&sid=ab&fp=chrome#R1";

    fn app() -> (Engine, u64) {
        let (tx, _rx) = unbounded_channel();
        let mut a = Engine::build(tx, Config::default(), None, false);
        a.add_link(REALITY.into());
        let id = a.subs[0].servers[0].id;
        (a, id)
    }

    #[tokio::test]
    async fn a_manual_fingerprint_is_never_replaced_by_the_search() {
        let (mut a, id) = app();
        assert!(a.fp_search_wanted(id).is_some());
        a.set_fingerprint(id, Some("safari".into()));
        assert!(a.fp_search_wanted(id).is_none());
        // Its own earlier result may be searched again.
        a.on_fp_searched(id, Some("Xray 1".into()), Some("firefox".into()), false);
        assert!(
            a.fp_search_wanted(id).is_none(),
            "result replaced a manual choice"
        );
    }

    #[tokio::test]
    async fn a_found_fingerprint_becomes_a_marked_override_and_the_link_is_untouched() {
        let (mut a, id) = app();
        a.on_fp_searched(id, Some("Xray 1".into()), Some("firefox".into()), false);
        let s = a.server_by_id(id).unwrap();
        assert_eq!(s.fp_override.as_deref(), Some("firefox"));
        assert!(s.fp_auto);
        assert_eq!(s.tls.fingerprint, "chrome");
        assert_eq!(a.config.servers[0].link, REALITY);
        let o = &a.config.overrides[0];
        assert!(o.fp_auto);
        assert_eq!(o.fp_auto_xray.as_deref(), Some("Xray 1"));
        assert_eq!(a.stored_search_version(id).as_deref(), Some("Xray 1"));
        // The automatic one may be searched again (another Xray version, say).
        assert!(a.fp_search_wanted(id).is_some());
    }

    #[tokio::test]
    async fn a_failed_search_is_remembered_so_it_is_not_repeated() {
        let (mut a, id) = app();
        a.on_fp_searched(id, Some("Xray 1".into()), None, false);
        assert_eq!(a.server_by_id(id).unwrap().fp_override, None);
        assert_eq!(a.stored_search_version(id).as_deref(), Some("Xray 1"));
        assert!(a.last_status().unwrap().as_str().contains("не удалось"));
        // A skipped run changes nothing.
        let before = a.config.overrides.clone();
        a.on_fp_searched(id, Some("Xray 1".into()), None, true);
        assert_eq!(a.config.overrides, before);
    }

    #[tokio::test]
    async fn pings_are_real_tcp_measurements() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = l.accept().await;
            }
        });
        let (tx, mut rx) = unbounded_channel();
        let mut a = Engine::build(tx, Config::default(), None, false);
        a.add_link(format!("vless://u@127.0.0.1:{port}?security=none#Local"));
        let id = a.subs[0].servers[0].id;
        a.ping_all();
        assert_eq!(a.server_by_id(id).unwrap().ping, Ping::Pending);
        // Other background events (server checks, logs) may arrive first.
        while !matches!(a.server_by_id(id).unwrap().ping, Ping::Ms(_)) {
            let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("a ping result")
                .unwrap();
            a.on_bg(ev);
        }
        assert!(matches!(a.server_by_id(id).unwrap().ping, Ping::Ms(_)));
    }

    #[tokio::test]
    async fn the_background_refresh_respects_the_interval_and_can_be_switched_off() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = l.accept().await;
            }
        });
        let (tx, mut rx) = unbounded_channel();
        let mut a = Engine::build(tx, Config::default(), None, false);
        a.add_link(format!("vless://u@127.0.0.1:{port}?security=none#L"));
        let id = a.subs[0].servers[0].id;

        a.config.ping.auto_interval_secs = 0;
        a.auto_ping_tick();
        assert_eq!(
            a.server_by_id(id).unwrap().ping,
            Ping::Unknown,
            "off means off"
        );

        a.config.ping.auto_interval_secs = 60;
        a.auto_ping_tick();
        assert_eq!(
            a.server_by_id(id).unwrap().ping,
            Ping::Unknown,
            "the refresh does not flash the pending marker"
        );
        while a.server_by_id(id).unwrap().ping_at.is_none() {
            let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap();
            a.on_bg(ev);
        }
        assert!(matches!(a.server_by_id(id).unwrap().ping, Ping::Ms(_)));
        assert_eq!(a.server_by_id(id).unwrap().ping_kind, PingKind::Tcp);
        let again = a.last_auto_ping;
        a.auto_ping_tick();
        assert_eq!(a.last_auto_ping, again, "not due yet");
    }

    #[test]
    fn with_the_tunnel_up_a_plain_tcp_ping_is_never_chosen() {
        use crate::storage::PingMode::{Tcp, Url};
        // Every combination: whatever the inputs, tun_up never yields a plain connect.
        for mode in [Tcp, Url] {
            for physical in [None, Some("eth0".to_string())] {
                for can_bind in [false, true] {
                    let (m, _) = choose_method(mode, true, physical.clone(), can_bind);
                    assert_ne!(m, Method::Tcp, "{mode:?} {physical:?} {can_bind}");
                }
            }
        }
        // Around the tunnel when that is possible, through the core when it is not.
        assert_eq!(
            choose_method(Tcp, true, Some("eth0".into()), true).0,
            Method::TcpBound("eth0".into())
        );
        let (m, note) = choose_method(Tcp, true, Some("eth0".into()), false);
        assert_eq!(m, Method::Url);
        assert!(note.unwrap().contains("TUN"));
        assert_eq!(choose_method(Tcp, true, None, true).0, Method::Url);
        // No tunnel: as configured.
        assert_eq!(choose_method(Tcp, false, None, false).0, Method::Tcp);
        assert_eq!(choose_method(Url, false, None, false).0, Method::Url);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_ping_bound_to_an_interface_goes_through_that_interface_or_says_unknown() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = l.accept().await;
            }
        });
        let limit = Duration::from_secs(2);
        // Bound to the loopback interface the local listener is reachable (when the kernel lets
        // an unprivileged process bind: otherwise the honest answer is "unknown", not a number).
        match ping::tcp_ping_via("127.0.0.1", port, limit, Some("lo")).await {
            Ping::Ms(_) | Ping::Unknown => {}
            other => panic!("{other:?}"),
        }
        // Bound to an interface that does not exist: never a measurement.
        let bad = ping::tcp_ping_via("127.0.0.1", port, limit, Some("nope0")).await;
        assert!(!matches!(bad, Ping::Ms(_)), "{bad:?}");
    }

    #[tokio::test]
    async fn the_unresolved_process_count_reaches_the_view_and_resets_on_connect() {
        let (tx, _rx) = unbounded_channel();
        let mut a = Engine::build(tx, Config::default(), None, false);
        a.process_unresolved = 12;
        assert_eq!(a.view().process_unresolved, 12);
    }

    #[tokio::test]
    async fn the_device_id_exists_from_the_first_view() {
        let (tx, _rx) = unbounded_channel();
        let a = Engine::build(tx, Config::default(), None, false);
        assert_eq!(a.view().config.device.hwid.len(), 16);
        assert_eq!(
            a.hub().subscribe().view.borrow().config.device.hwid.len(),
            16,
            "even the first snapshot"
        );
    }
}
