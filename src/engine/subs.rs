//! Subscriptions: adding, updating (by hand and on a schedule), caching.

use super::*;
use crate::event::SubUpdate;
use crate::model::subscription::unix_now;
use crate::net::fetch;
use crate::parser::subscription::parse_body;
use crate::storage::{CachedSubscription, SubscriptionCache, SubscriptionConfig};
use std::time::Instant;

/// Downloads and parses a subscription (off the UI thread).
pub(super) async fn download(
    url: &str,
    user_agent: &str,
    device: &crate::net::device::DeviceInfo,
) -> Result<Box<SubUpdate>, String> {
    let fetched = fetch::fetch(url, user_agent, device).await?;
    let parsed = parse_body(&fetched.body).map_err(|e| e.to_string())?;
    Ok(Box::new(SubUpdate {
        servers: parsed.servers,
        skipped: parsed.skipped,
        info: fetched.info,
        title: fetched.title,
    }))
}

/// How often the schedule is looked at.
const AUTO_CHECK_EVERY: Duration = Duration::from_secs(60);

fn host_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "subscription".into())
}

impl Engine {
    /// Groups for `[[subscriptions]]`, filled from the cache; call from `build`.
    pub(super) fn subscription_groups(
        config: &Config,
        cache: &SubscriptionCache,
        next_id: &mut u64,
        load_errors: &mut Vec<String>,
    ) -> Vec<Subscription> {
        let mut groups = Vec::new();
        for sc in &config.subscriptions {
            let cached = cache.get(&sc.name).cloned().unwrap_or_default();
            let mut servers = Vec::new();
            for link in &cached.links {
                match parser::parse_link(link) {
                    Ok(mut s) => {
                        *next_id += 1;
                        s.id = *next_id;
                        servers.push(s);
                    }
                    Err(e) => load_errors.push(format!("{}: {e}", sc.name)),
                }
            }
            for s in &mut servers {
                s.hidden = config
                    .hidden
                    .iter()
                    .any(|h| h.group == sc.name && h.key == hide_key(s));
            }
            groups.push(Subscription {
                name: sc.name.clone(),
                servers,
                collapsed: false,
                info: cached.info,
                updated: cached.updated,
                is_remote: true,
            });
        }
        groups
    }

    /// How this installation introduces itself to subscription panels.
    fn device(&self) -> crate::net::device::DeviceInfo {
        crate::net::device::DeviceInfo::current(&self.config.device.hwid)
    }

    pub(super) fn save_subscription_cache(&mut self) {
        let Some(storage) = &self.storage else { return };
        let cache: SubscriptionCache = self
            .subs
            .iter()
            .filter(|s| s.is_remote)
            .map(|s| {
                (
                    s.name.clone(),
                    CachedSubscription {
                        links: s.servers.iter().map(|x| x.link.clone()).collect(),
                        info: s.info.clone(),
                        updated: s.updated,
                    },
                )
            })
            .collect();
        if let Err(e) = storage.save_subscriptions(&cache) {
            self.log(Level::Error, format!("[Error] {e}"));
        }
    }

    /// `u`: update every subscription now.
    pub(super) fn update_subscriptions(&mut self) {
        if self.config.subscriptions.is_empty() {
            self.status(crate::t!("eng.no_subs"));
            return;
        }
        let names: Vec<String> = self
            .config
            .subscriptions
            .iter()
            .map(|s| s.name.clone())
            .collect();
        let started = names.into_iter().filter(|n| self.spawn_update(n)).count();
        self.status(if started > 0 {
            crate::t!("eng.subs_updating")
        } else {
            crate::t!("eng.subs_already")
        });
    }

    /// Starts one update unless it is already running. `true` if it started.
    fn spawn_update(&mut self, name: &str) -> bool {
        let Some(sc) = self
            .config
            .subscriptions
            .iter()
            .find(|s| s.name == name)
            .cloned()
        else {
            return false;
        };
        if !self.updating.insert(name.to_string()) {
            return false;
        }
        let tx = self.tx.clone();
        let device = self.device();
        tokio::spawn(async move {
            let result = download(&sc.url, &sc.user_agent, &device).await;
            let _ = tx.send(BgEvent::SubFetched {
                name: sc.name,
                result,
            });
        });
        true
    }

    /// Called from the tick: updates whatever is due by `auto_update_hours`.
    pub(super) fn auto_update_tick(&mut self) {
        if self
            .last_auto_check
            .is_some_and(|t| t.elapsed() < AUTO_CHECK_EVERY)
        {
            return;
        }
        self.last_auto_check = Some(Instant::now());
        let now = unix_now();
        let due: Vec<String> = self
            .config
            .subscriptions
            .iter()
            .filter(|sc| sc.auto_update_hours > 0)
            .filter(|sc| {
                let updated = self
                    .subs
                    .iter()
                    .find(|g| g.name == sc.name)
                    .and_then(|g| g.updated);
                updated.is_none_or(|t| now - t >= i64::from(sc.auto_update_hours) * 3600)
            })
            // A subscription that failed recently is not retried every minute.
            .filter(|sc| {
                self.failed_at
                    .get(&sc.name)
                    .is_none_or(|t| t.elapsed() > Duration::from_secs(600))
            })
            .map(|sc| sc.name.clone())
            .collect();
        for name in due {
            self.spawn_update(&name);
        }
    }

    pub(super) fn on_sub_fetched(&mut self, name: String, result: Result<Box<SubUpdate>, String>) {
        self.updating.remove(&name);
        match result {
            Err(e) => {
                // The old list stays: only a warning.
                self.failed_at.insert(name.clone(), Instant::now());
                self.logt(Level::Warning, || {
                    crate::t!("eng.sub_failed_log", name = name, error = e)
                });
                self.status(crate::t!("eng.sub_failed_status", name = name, error = e));
            }
            Ok(update) => {
                self.failed_at.remove(&name);
                self.apply_update(&name, *update);
            }
        }
    }

    /// Replaces a group's servers with the new list, keeping ids (so a live connection and the
    /// selection stay valid) for servers that have the same name, host and port.
    fn apply_update(&mut self, name: &str, update: SubUpdate) {
        let Some(gi) = self.subs.iter().position(|s| s.name == name) else {
            return;
        };
        let mut old: Vec<Server> = std::mem::take(&mut self.subs[gi].servers);
        let mut servers = Vec::with_capacity(update.servers.len());
        for mut s in update.servers {
            let key = override_key(name, &s);
            match old.iter().position(|o| override_key(name, o) == key) {
                Some(pos) => {
                    let o = old.remove(pos);
                    s.id = o.id;
                    s.ping = o.ping;
                }
                None => {
                    self.next_id += 1;
                    s.id = self.next_id;
                }
            }
            apply_overrides(&self.config, name, &mut s);
            s.hidden = self
                .config
                .hidden
                .iter()
                .any(|h| h.group == name && h.key == hide_key(&s));
            servers.push(s);
        }
        let count = servers.len();
        let gone = old.len();
        let sub = &mut self.subs[gi];
        sub.servers = servers;
        sub.info = update.info;
        sub.updated = Some(unix_now());
        let skipped = update.skipped;
        self.logt(Level::Info, || {
            crate::t!(
                "eng.sub_updated_log",
                name = name,
                count = count,
                gone = if gone > 0 {
                    crate::t!("eng.sub_gone", n = gone)
                } else {
                    String::new()
                },
                skipped = if skipped > 0 {
                    crate::t!("eng.sub_skipped", n = skipped)
                } else {
                    String::new()
                }
            )
        });
        self.status(crate::t!(
            "eng.sub_updated_status",
            name = name,
            count = count
        ));
        self.save_subscription_cache();
        // Only servers whose config changed cost a real `xray run -test`: the cache knows the rest.
        let to_check: Vec<Server> = self.subs[gi]
            .servers
            .iter()
            .filter(|s| s.is_supported())
            .cloned()
            .collect();
        self.spawn_checks(to_check);
    }

    /// `a` with an http(s) link: download first, add the subscription only if it works.
    pub(super) fn add_subscription_url(&mut self, url: String) {
        if self.config.subscriptions.iter().any(|s| s.url == url) {
            self.error_alert(crate::t!("eng.sub_dup"));
            return;
        }
        if url::Url::parse(&url).is_err() {
            self.error_alert(crate::t!("eng.sub_bad_url"));
            return;
        }
        self.status(crate::t!("eng.sub_loading"));
        let tx = self.tx.clone();
        let user_agent = fetch::DEFAULT_USER_AGENT.to_string();
        let device = self.device();
        tokio::spawn(async move {
            let result = download(&url, &user_agent, &device).await;
            let _ = tx.send(BgEvent::SubAdded {
                url,
                user_agent,
                result,
            });
        });
    }

    pub(super) fn on_sub_added(
        &mut self,
        url: String,
        user_agent: String,
        result: Result<Box<SubUpdate>, String>,
    ) {
        let update = match result {
            Ok(u) => u,
            Err(e) => {
                self.logt(Level::Warning, || {
                    crate::t!("eng.sub_add_failed_log", error = e)
                });
                self.error_alert(crate::t!("eng.sub_add_failed", error = e));
                return;
            }
        };
        let base = update
            .title
            .clone()
            .unwrap_or_else(|| host_of(&url))
            .replace('/', "-");
        let mut name = base.clone();
        let mut n = 1;
        while name == MANUAL_GROUP || self.subs.iter().any(|s| s.name == name) {
            n += 1;
            name = format!("{base} {n}");
        }
        self.config.subscriptions.push(SubscriptionConfig {
            name: name.clone(),
            url,
            user_agent,
            ..SubscriptionConfig::default()
        });
        self.subs.insert(
            self.config.subscriptions.len() - 1,
            Subscription {
                name: name.clone(),
                servers: Vec::new(),
                collapsed: false,
                info: None,
                updated: None,
                is_remote: true,
            },
        );
        // Remote groups come first, in config order; the manual group stays last.
        self.subs.sort_by_key(|s| s.name == MANUAL_GROUP);
        self.apply_update(&name, *update);
        self.save_config();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::fetch::parse_userinfo;
    use tokio::sync::mpsc::unbounded_channel;

    const A: &str = "vless://u@a.example.com:443?security=tls#A";
    const B: &str = "vless://u@b.example.com:443?security=tls#B";
    const C: &str = "vless://u@c.example.com:443?security=tls#C";

    fn update(links: &[&str]) -> Box<SubUpdate> {
        Box::new(SubUpdate {
            servers: links
                .iter()
                .map(|l| parser::parse_link(l).unwrap())
                .collect(),
            skipped: 0,
            info: parse_userinfo("download=5; total=10"),
            title: Some("Prov".into()),
        })
    }

    fn app_in(dir: &std::path::Path) -> Engine {
        let (tx, _rx) = unbounded_channel();
        Engine::build(tx, Config::default(), Some(Storage::new(dir)), false)
    }

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("elf-gate-subs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[tokio::test]
    async fn adding_a_subscription_creates_a_group_a_config_entry_and_a_cache() {
        let d = dir("add");
        let mut a = app_in(&d);
        a.on_sub_added(
            "https://prov.example/sub".into(),
            "ua".into(),
            Ok(update(&[A, B])),
        );
        assert_eq!(a.subs.len(), 1);
        assert_eq!(a.subs[0].name, "Prov");
        assert!(a.subs[0].is_remote);
        assert_eq!(a.subs[0].servers.len(), 2);
        assert_eq!(a.config.subscriptions[0].url, "https://prov.example/sub");
        assert_eq!(a.subs[0].info.as_ref().unwrap().total, 10);

        // A fresh start has the same list without any network.
        let storage = Storage::new(&d);
        let (tx, _rx) = unbounded_channel();
        let b = Engine::build(tx, storage.load().unwrap(), Some(storage), false);
        assert_eq!(b.subs[0].servers.len(), 2);
        assert_eq!(b.subs[0].servers[1].name, "B");
        assert!(b.subs[0].updated.is_some());
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn a_failed_download_adds_nothing_and_a_failed_update_keeps_the_old_list() {
        let d = dir("fail");
        let mut a = app_in(&d);
        a.on_sub_added(
            "https://x.example/s".into(),
            "ua".into(),
            Err("нет сети".into()),
        );
        assert!(matches!(a.alerts().last(), Some(Alert::Error(_))));
        assert!(a.subs.is_empty() && a.config.subscriptions.is_empty());

        a.on_sub_added(
            "https://x.example/s".into(),
            "ua".into(),
            Ok(update(&[A, B])),
        );
        let name = a.subs[0].name.clone();
        a.updating.insert(name.clone());
        a.on_sub_fetched(name.clone(), Err("timeout".into()));
        assert_eq!(a.subs[0].servers.len(), 2, "old servers stay");
        assert!(!a.updating.contains(&name));
        assert!(a.last_status().unwrap().as_str().contains("timeout"));
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn an_update_keeps_ids_of_unchanged_servers_and_overrides() {
        let d = dir("ids");
        let mut a = app_in(&d);
        a.on_sub_added(
            "https://x.example/s".into(),
            "ua".into(),
            Ok(update(&[A, B])),
        );
        let name = a.subs[0].name.clone();
        let id_b = a.subs[0].servers[1].id;
        a.config.overrides.push({
            let mut o = ServerOverride::new(format!("{name}/B|b.example.com:443"));
            o.fp = Some("firefox".into());
            o
        });
        a.conn = Conn::Connected(id_b);

        a.on_sub_fetched(name.clone(), Ok(update(&[B, C])));
        let servers = &a.subs[0].servers;
        assert_eq!(servers.len(), 2);
        assert_eq!(
            servers[0].id, id_b,
            "B keeps its id, so the live connection stays valid"
        );
        assert_eq!(servers[0].fp_override.as_deref(), Some("firefox"));
        assert_ne!(servers[1].id, id_b);
        assert!(a.server_by_id(id_b).is_some());
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn duplicate_names_get_a_suffix() {
        let d = dir("dup");
        let mut a = app_in(&d);
        a.on_sub_added("https://x.example/1".into(), "ua".into(), Ok(update(&[A])));
        a.on_sub_added("https://x.example/2".into(), "ua".into(), Ok(update(&[B])));
        let names: Vec<_> = a.subs.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["Prov", "Prov 2"]);
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn the_schedule_updates_only_what_is_due() {
        let d = dir("auto");
        let mut a = app_in(&d);
        a.on_sub_added("https://x.example/1".into(), "ua".into(), Ok(update(&[A])));
        let name = a.subs[0].name.clone();
        // Fresh: nothing is due.
        a.last_auto_check = None;
        a.auto_update_tick();
        assert!(a.updating.is_empty());
        // Old enough: an update starts, once.
        a.subs[0].updated = Some(unix_now() - 13 * 3600);
        a.last_auto_check = None;
        a.auto_update_tick();
        assert!(a.updating.contains(&name));
        // Switched off: never.
        a.updating.clear();
        a.config.subscriptions[0].auto_update_hours = 0;
        a.last_auto_check = None;
        a.auto_update_tick();
        assert!(a.updating.is_empty());
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn deleting_a_subscription_removes_its_config_entry() {
        let d = dir("del");
        let mut a = app_in(&d);
        a.on_sub_added("https://x.example/1".into(), "ua".into(), Ok(update(&[A])));
        let n = a.subs[0].name.clone();
        a.delete_group(&n);
        assert!(a.subs.is_empty());
        assert!(a.config.subscriptions.is_empty());
        let storage = Storage::new(&d);
        assert!(storage.load().unwrap().subscriptions.is_empty());
        assert!(storage.load_subscriptions().is_empty());
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn a_json_subscription_gives_chain_servers_and_notices_and_survives_the_cache() {
        use crate::model::fullconfig::tests::{balanced, chain_dialer};
        let d = dir("json");
        let mut a = app_in(&d);
        let body = serde_json::to_string(&serde_json::json!([
            { "remarks": "⬇ Обход глушилок ⬇", "outbounds": [{ "tag": "direct", "protocol": "freedom" }] },
            chain_dialer(),
            balanced()
        ]))
        .unwrap();
        let parsed = crate::parser::subscription::parse_body(&body).unwrap();
        let update = Box::new(SubUpdate {
            servers: parsed.servers,
            skipped: parsed.skipped,
            info: None,
            title: Some("Panel".into()),
        });
        a.on_sub_added("https://panel.example/sub".into(), "ua".into(), Ok(update));
        let g = &a.subs[0];
        assert_eq!(g.servers.len(), 3);
        assert!(g.servers[0].info_only && g.servers[1].full.is_some());

        // A title is a notice, not an error, and never starts anything.
        let title = g.servers[0].id;
        a.handle_cmd(Cmd::Connect(title));
        assert!(matches!(a.alerts().last(), Some(Alert::Notice(_))));
        assert_eq!(a.conn, Conn::Disconnected);

        // The whole chain is in the cache file and comes back as a chain.
        let storage = Storage::new(&d);
        let (tx, _rx) = unbounded_channel();
        let b = Engine::build(tx, storage.load().unwrap(), Some(storage), false);
        assert_eq!(b.subs[0].servers[1].full.as_ref().unwrap().hops, 2);
        // The interface copy has no chain contents.
        let view = a.view();
        assert!(view.groups[0].servers[1]
            .full
            .as_ref()
            .unwrap()
            .outbounds
            .is_empty());
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn the_hwid_is_made_once_and_kept() {
        let d = dir("hwid");
        let a = app_in(&d);
        let first = a.config.device.hwid.clone();
        assert_eq!(first.len(), 16);
        let storage = Storage::new(&d);
        let saved = storage.load().unwrap();
        assert_eq!(saved.device.hwid, first, "written to config.toml");
        let (tx, _rx) = unbounded_channel();
        let b = Engine::build(tx, saved, Some(storage), false);
        assert_eq!(b.config.device.hwid, first, "the same on the next run");
        let _ = std::fs::remove_dir_all(d);
    }

    // ---- deleting from subscriptions (bug report) ----

    fn reload(d: &std::path::Path) -> Engine {
        let storage = Storage::new(d);
        let (tx, _rx) = unbounded_channel();
        Engine::build(tx, storage.load().unwrap(), Some(storage), false)
    }

    fn visible(e: &Engine, group: &str) -> Vec<String> {
        e.subs
            .iter()
            .find(|g| g.name == group)
            .map(|g| {
                g.servers
                    .iter()
                    .filter(|s| !s.hidden)
                    .map(|s| s.name.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn a_deleted_subscription_server_stays_gone_after_a_restart_and_an_update() {
        let d = dir("hide");
        let mut a = app_in(&d);
        a.on_sub_added(
            "https://x.example/s".into(),
            "ua".into(),
            Ok(update(&[A, B])),
        );
        let name = a.subs[0].name.clone();
        let id_a = a.subs[0].servers[0].id;
        a.handle_cmd(Cmd::DeleteServer(id_a));
        assert_eq!(visible(&a, &name), ["B"]);

        // The daemon restarts: still hidden (it was saved, not just dropped from memory).
        let mut b = reload(&d);
        assert_eq!(visible(&b, &name), ["B"], "hidden after a restart");
        // The provider still lists it: the update must not bring it back.
        b.on_sub_fetched(name.clone(), Ok(update(&[A, B, C])));
        assert_eq!(visible(&b, &name), ["B", "C"]);
        // It can be restored from the subscription's menu.
        let id_a = b.subs[0].servers.iter().find(|s| s.name == "A").unwrap().id;
        b.handle_cmd(Cmd::UnhideServer(id_a));
        assert_eq!(visible(&b, &name), ["A", "B", "C"]);
        let c = reload(&d);
        assert_eq!(visible(&c, &name), ["A", "B", "C"], "and that is saved too");
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn a_manual_server_is_really_deleted() {
        let d = dir("manual");
        let mut a = app_in(&d);
        a.add_link(A.into());
        let id = a.subs[0].servers[0].id;
        a.handle_cmd(Cmd::DeleteServer(id));
        assert!(a.subs.is_empty());
        assert!(reload(&d).subs.is_empty());
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn a_subscription_can_be_deleted_in_any_state() {
        for state in ["empty", "all hidden", "only placeholders", "failed update"] {
            let d = dir(&format!("del-{}", state.replace(' ', "-")));
            let mut a = app_in(&d);
            a.on_sub_added("https://x.example/s".into(), "ua".into(), Ok(update(&[A])));
            let name = a.subs[0].name.clone();
            match state {
                "empty" => {
                    a.subs[0].servers.clear();
                }
                "all hidden" => {
                    let id = a.subs[0].servers[0].id;
                    a.handle_cmd(Cmd::DeleteServer(id));
                    assert!(visible(&a, &name).is_empty());
                }
                "only placeholders" => {
                    let stub = parser::parse_link(
                        "vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?security=none#Stub",
                    )
                    .unwrap();
                    a.subs[0].servers = vec![stub];
                }
                _ => {
                    a.updating.insert(name.clone());
                    a.on_sub_fetched(name.clone(), Err("нет сети".into()));
                }
            }
            a.handle_cmd(Cmd::DeleteGroup(name.clone()));
            assert!(a.subs.is_empty(), "{state}");
            assert!(a.config.subscriptions.is_empty(), "{state}");
            assert!(
                a.config.hidden.is_empty(),
                "{state}: its hidden keys go too"
            );
            let b = reload(&d);
            assert!(
                b.subs.is_empty() && b.config.subscriptions.is_empty(),
                "{state}: gone after a restart"
            );
            assert!(
                Storage::new(&d).load_subscriptions().is_empty(),
                "{state}: cache entry gone"
            );
            let _ = std::fs::remove_dir_all(d);
        }
    }

    #[tokio::test]
    async fn deleting_the_connected_server_disconnects_first() {
        let d = dir("conn");
        let mut a = app_in(&d);
        a.on_sub_added(
            "https://x.example/s".into(),
            "ua".into(),
            Ok(update(&[A, B])),
        );
        let id = a.subs[0].servers[0].id;
        a.conn = Conn::Connected(id);
        a.handle_cmd(Cmd::DeleteServer(id));
        assert_eq!(a.conn, Conn::Disconnected);
        let _ = std::fs::remove_dir_all(d);
    }
}
