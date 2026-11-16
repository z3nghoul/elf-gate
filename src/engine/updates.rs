//! The notice about a new version: a check at start and once a day, results kept in the state.

use super::*;
use crate::model::subscription::unix_now;
use crate::update::{self, Release, Version};

/// How often the schedule is looked at.
const LOOK_EVERY: Duration = Duration::from_secs(60);
/// After a failed request the next one waits this long (the failure is only in the log).
const RETRY_AFTER: Duration = Duration::from_secs(3600);
/// Releases kept in the state; the notice needs the newest ones only.
const KEEP_RELEASES: usize = 10;

impl Engine {
    /// The release to tell the user about, if there is one.
    pub(super) fn current_update(&self) -> Option<Release> {
        let u = &self.config.updates;
        if !u.check {
            return None;
        }
        update::newest(
            &self.releases,
            crate::build_info::VERSION,
            u.channel,
            u.skipped.as_deref(),
        )
        .cloned()
    }

    /// Called from the tick: starts a check when the schedule says so.
    pub(super) fn update_tick(&mut self) {
        if !self.update_checks || !self.config.updates.check || self.update_busy {
            return;
        }
        if self.update_looked.is_some_and(|t| t.elapsed() < LOOK_EVERY) {
            return;
        }
        self.update_looked = Some(Instant::now());
        let state = self.state_store.as_ref().and_then(|s| s.load().ok());
        // The first look is the startup one: what the last check found is shown at once.
        let running = std::mem::replace(&mut self.update_ran, true);
        if !running {
            if let Some(state) = &state {
                self.releases = state.releases.clone();
            }
        }
        if self
            .update_failed
            .is_some_and(|t| t.elapsed() < RETRY_AFTER)
        {
            return;
        }
        let last = state.and_then(|s| s.last_update_check);
        if !update::due(last, unix_now(), running) {
            return;
        }
        self.update_busy = true;
        // Direct first. When that fails and the VPN is up, the local proxy of the core may
        // still reach GitHub (it is blocked in some places).
        let socks = matches!(self.conn, Conn::Connected(_)).then_some(self.config.core.socks_port);
        let tx = self.tx.clone();
        self.spawn(async move {
            let mut result = update::fetch(None).await;
            if let (Err(direct), Some(port)) = (&result, socks) {
                let direct = direct.clone();
                result = update::fetch(Some(port))
                    .await
                    .map_err(|via| format!("{direct}; through the local proxy: {via}"));
            }
            let _ = tx.send(BgEvent::UpdateChecked(result));
        });
    }

    pub(super) fn on_update_checked(&mut self, result: Result<Vec<Release>, String>) {
        self.update_busy = false;
        match result {
            Err(e) => {
                self.update_failed = Some(Instant::now());
                self.log(Level::Warning, format!("update check failed: {e}"));
            }
            Ok(mut releases) => {
                self.update_failed = None;
                releases.sort_by_key(|r| std::cmp::Reverse(Version::parse(&r.version)));
                releases.truncate(KEEP_RELEASES);
                self.releases = releases;
                self.save_update_state();
                if let Some(r) = self.current_update() {
                    self.log(Level::Info, format!("new version available: {}", r.version));
                }
            }
        }
    }

    fn save_update_state(&mut self) {
        let Some(store) = &self.state_store else {
            return;
        };
        if let Ok(mut state) = store.load() {
            state.last_update_check = Some(unix_now());
            state.releases = self.releases.clone();
            if let Err(e) = store.save(&state) {
                self.log(Level::Warning, format!("update check not saved: {e}"));
            }
        }
    }

    /// "Do not remind me about this version".
    pub(super) fn skip_update(&mut self, version: String) {
        self.config.updates.skipped = Some(version);
        self.save_config();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::UpdateChannel;
    use crate::update::RELEASES_PAGE;
    use tokio::sync::mpsc::unbounded_channel;

    fn rel(version: &str, prerelease: bool) -> Release {
        Release {
            version: version.into(),
            prerelease,
            notes: format!("notes {version}"),
            url: RELEASES_PAGE.into(),
        }
    }

    fn engine() -> Engine {
        let (tx, _rx) = unbounded_channel();
        Engine::new(tx)
    }

    #[tokio::test]
    async fn a_newer_release_reaches_the_view_and_the_channel_and_the_switch_decide() {
        let mut e = engine();
        e.releases = vec![
            rel("99.0.0-rc.1", true),
            rel("98.0.0", false),
            rel("0.0.1", false),
        ];
        assert_eq!(e.view().update.unwrap().version, "98.0.0");
        e.handle_cmd(Cmd::Set(crate::proto::Setting::UpdateChannel(
            UpdateChannel::Test,
        )));
        assert_eq!(e.view().update.unwrap().version, "99.0.0-rc.1");
        e.handle_cmd(Cmd::Set(crate::proto::Setting::CheckUpdates(false)));
        assert!(e.view().update.is_none());
        e.handle_cmd(Cmd::Set(crate::proto::Setting::CheckUpdates(true)));
        assert!(e.view().update.is_some());
    }

    #[tokio::test]
    async fn skipping_hides_that_version_and_is_saved() {
        let dir = crate::test_support::TempDir::new("skip-update");
        let storage = Storage::new(dir.path());
        let (tx, _rx) = unbounded_channel();
        let mut e = Engine::build(tx, Config::default(), Some(storage.clone()), false);
        e.releases = vec![rel("98.0.0", false), rel("97.0.0", false)];
        e.handle_cmd(Cmd::SkipUpdate("98.0.0".into()));
        assert_eq!(e.view().update.unwrap().version, "97.0.0");
        assert_eq!(
            storage.load().unwrap().updates.skipped.as_deref(),
            Some("98.0.0")
        );
        e.releases = vec![rel("99.0.0", false), rel("98.0.0", false)];
        assert_eq!(e.view().update.unwrap().version, "99.0.0");
    }

    #[tokio::test]
    async fn a_check_result_is_kept_in_the_state_and_a_failure_only_in_the_log() {
        let dir = crate::test_support::TempDir::new("update-state");
        let store = StateStore::new(dir.path());
        let mut e = engine().with_state_store(store.clone());
        e.update_busy = true;
        e.on_bg(BgEvent::UpdateChecked(Ok(vec![
            rel("1.0.0", false),
            rel("98.0.0", false),
        ])));
        assert!(!e.update_busy);
        let saved = store.load().unwrap();
        assert!(saved.last_update_check.is_some());
        assert_eq!(saved.releases[0].version, "98.0.0");
        assert!(e.logged("new version available: 98.0.0"));

        e.update_busy = true;
        e.on_bg(BgEvent::UpdateChecked(Err("HTTP 403".into())));
        assert!(!e.update_busy && e.update_failed.is_some());
        assert!(e.logged("update check failed: HTTP 403"));
        // The known releases stay, no alert and no status text.
        assert!(e.view().update.is_some());
        assert!(e.alerts().is_empty());
    }

    #[tokio::test]
    async fn the_schedule_reads_the_state_and_does_not_ask_when_the_last_check_is_young() {
        let dir = crate::test_support::TempDir::new("update-state");
        let store = StateStore::new(dir.path());
        store
            .save(&crate::storage::State {
                last_update_check: Some(unix_now() - 60),
                releases: vec![rel("98.0.0", false)],
                ..Default::default()
            })
            .unwrap();
        let mut e = engine().with_state_store(store).with_update_checks();
        e.update_tick();
        // Young check: no request, but the notice from the state is there at once.
        assert!(!e.update_busy);
        assert_eq!(e.view().update.unwrap().version, "98.0.0");
        // Looked at once: the next look is a minute away.
        assert!(e.update_looked.is_some() && e.update_ran);
    }

    #[tokio::test]
    async fn without_the_switch_or_the_setting_nothing_is_asked() {
        let mut e = engine();
        e.update_tick();
        assert!(!e.update_busy && !e.update_ran);
        let mut e = engine().with_update_checks();
        e.config.updates.check = false;
        e.update_tick();
        assert!(!e.update_busy && !e.update_ran);
    }
}
