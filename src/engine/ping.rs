//! Pinging servers and the automatic TLS fingerprint search.

use super::*;
use crate::model::server::Security;
use crate::net::ping;
use crate::storage::PingMode;
use crate::xray::process::resolve_binary;

impl Engine {
    pub(super) fn ping_all(&mut self) {
        let real: Vec<Server> = self
            .subs
            .iter()
            .flat_map(|s| s.servers.iter())
            .filter(|s| s.is_supported() && !s.link.is_empty())
            .cloned()
            .collect();
        if self.mock {
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
                self.status("Нет серверов для пинга");
            }
            return;
        }
        // A throw-away core cannot measure anything while the TUN is up: its connection to
        // the server would enter the tunnel. TCP probes of elf-gate itself stay direct.
        let tun_up = self.tun_active && matches!(self.conn, Conn::Connected(_));
        let mut mode = self.config.ping.mode;
        if mode == PingMode::Url && tun_up {
            mode = PingMode::Tcp;
            self.status("В режиме TUN пинг по URL недоступен, измерен TCP-пинг");
        }
        let binary = if mode == PingMode::Url {
            match resolve_binary(&self.config.core.xray_path) {
                Ok(b) => Some(b),
                Err(e) => {
                    self.status(format!("Пинг по URL: {e}"));
                    return;
                }
            }
        } else {
            None
        };
        let limit = Duration::from_millis(self.config.ping.timeout_ms.max(500));
        for server in real {
            self.set_ping(server.id, Ping::Pending);
            let tx = self.tx.clone();
            let core = self.config.core.clone();
            let cfg = self.config.ping.clone();
            let run_dir = self.run_dir.clone();
            let binary = binary.clone();
            tokio::spawn(async move {
                let (result, suspect) = match binary {
                    Some(bin) => ping::url_ping(&bin, &core, &server, &cfg, &run_dir).await,
                    None => (
                        ping::tcp_ping(&server.address, server.port, limit).await,
                        false,
                    ),
                };
                let _ = tx.send(BgEvent::Ping {
                    id: server.id,
                    result,
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
        self.log(
            Level::Info,
            format!(
                "{}: сервер отвечает по TCP, но запрос через него не проходит; подбираю fp",
                server.name
            ),
        );
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
                self.log(
                    Level::Info,
                    format!("{name}: fp подобран автоматически: {fp}"),
                );
                self.status(format!("{name}: подобран fp={fp}"));
            }
            None => {
                self.log(
                    Level::Warning,
                    format!(
                        "[Warning] {name}: ни один fp не помог. Проверьте ключ, SNI, shortId и порт на сервере"
                    ),
                );
                self.status(format!("{name}: подобрать fp не удалось"));
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
}
