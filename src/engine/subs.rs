//! Subscriptions: adding, updating (by hand and on a schedule), caching.

use super::*;
use crate::event::SubUpdate;
use crate::model::subscription::unix_now;
use crate::net::fetch;
use crate::parser::subscription::parse_body;
use crate::storage::{CachedSubscription, SubscriptionCache, SubscriptionConfig};
use std::time::Instant;

/// Downloads and parses a subscription (off the UI thread).
pub(super) async fn download(url: &str, user_agent: &str) -> Result<Box<SubUpdate>, String> {
    let fetched = fetch::fetch(url, user_agent).await?;
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
            self.status("Нет подписок: добавьте ссылку на подписку клавишей a");
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
            "Обновление подписок..."
        } else {
            "Обновление уже идёт"
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
        tokio::spawn(async move {
            let result = download(&sc.url, &sc.user_agent).await;
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
                self.log(
                    Level::Warning,
                    format!("[Warning] подписка «{name}» не обновлена: {e}"),
                );
                self.status(format!("Подписка «{name}»: {e}"));
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
            servers.push(s);
        }
        let count = servers.len();
        let gone = old.len();
        let sub = &mut self.subs[gi];
        sub.servers = servers;
        sub.info = update.info;
        sub.updated = Some(unix_now());
        self.log(
            Level::Info,
            format!(
                "подписка «{name}» обновлена: {count} серверов{}{}",
                if gone > 0 {
                    format!(", убрано {gone}")
                } else {
                    String::new()
                },
                if update.skipped > 0 {
                    format!(", пропущено строк: {}", update.skipped)
                } else {
                    String::new()
                }
            ),
        );
        self.status(format!("Подписка «{name}»: {count} серверов"));
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
            self.error_alert("Эта подписка уже добавлена");
            return;
        }
        if url::Url::parse(&url).is_err() {
            self.error_alert("Некорректный адрес подписки");
            return;
        }
        self.status("Загрузка подписки...");
        let tx = self.tx.clone();
        let user_agent = fetch::DEFAULT_USER_AGENT.to_string();
        tokio::spawn(async move {
            let result = download(&url, &user_agent).await;
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
                self.log(
                    Level::Warning,
                    format!("[Warning] подписка не добавлена: {e}"),
                );
                self.error_alert(format!("Подписку не удалось загрузить:\n{e}"));
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

    fn app_in(dir: &std::path::Path) -> AppState {
        let (tx, _rx) = unbounded_channel();
        AppState::build(tx, Config::default(), Some(Storage::new(dir)), false)
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
        let b = AppState::build(tx, storage.load().unwrap(), Some(storage), false);
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
        assert!(matches!(a.popup, Some(Popup::Error(_))));
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
        assert!(a.status.as_deref().unwrap().contains("timeout"));
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
        a.confirm(ConfirmKind::DeleteGroup(0));
        assert!(a.subs.is_empty());
        assert!(a.config.subscriptions.is_empty());
        let storage = Storage::new(&d);
        assert!(storage.load().unwrap().subscriptions.is_empty());
        assert!(storage.load_subscriptions().is_empty());
        let _ = std::fs::remove_dir_all(d);
    }
}
