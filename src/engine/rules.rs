//! Routing rules and presets: the data side. (The screen, the cursor and the pickers belong
//! to the interface.)

use super::*;
use crate::model::rule::{validate, RoutingMode};
use crate::xray::config::Plan;
use crate::xray::routing_api::{rules_of, without_rules};
use serde_json::Value;

impl Engine {
    pub(crate) fn rules_toggle(&mut self, item: RuleRef) {
        match item {
            RuleRef::Preset(id) => {
                if !builtin_presets().iter().any(|p| p.id == id) {
                    return;
                }
                let list = &mut self.config.presets.enabled;
                if let Some(pos) = list.iter().position(|p| *p == id) {
                    list.remove(pos);
                } else {
                    list.push(id);
                }
            }
            RuleRef::Rule(i) => match self.config.rules.get_mut(i) {
                Some(rule) => rule.enabled = !rule.enabled,
                None => return,
            },
        }
        self.rules_changed(true);
    }

    pub(crate) fn rules_delete(&mut self, i: usize) {
        if i < self.config.rules.len() {
            self.config.rules.remove(i);
            self.rules_changed(true);
        }
    }

    pub(crate) fn rules_set_routing(&mut self, mode: RoutingMode) {
        if self.config.mode.routing != mode {
            self.config.mode.routing = mode;
            // The mode changes more than the list of rules (DNS, the last rule): a restart.
            self.rules_changed(false);
        }
    }

    pub(crate) fn submit_rule(&mut self, kind: RuleKind, text: String) {
        match validate(kind, &text) {
            Ok(value) => self.add_rule(kind, value),
            Err(e) => self.error_alert(crate::t!("eng.rule_rejected", error = e)),
        }
    }

    fn add_rule(&mut self, kind: RuleKind, value: String) {
        if self
            .config
            .rules
            .iter()
            .any(|r| r.kind == kind && r.value == value)
        {
            self.error_alert(crate::t!("eng.rule_exists"));
            return;
        }
        self.config.rules.push(Rule::new(kind, value));
        self.rules_changed(true);
    }

    /// Saves. A running core takes the new rules through its API when only its rule list
    /// changes (`live`); anything else it can only learn from a restart, which the user is
    /// asked for.
    fn rules_changed(&mut self, live: bool) {
        self.save_config();
        let Conn::Connected(id) = self.conn else {
            return;
        };
        if self.core.is_none() && self.live.is_none() {
            return;
        }
        if live && self.apply_rules_live(id) {
            return;
        }
        self.alert(Alert::Ask {
            text: crate::t!("eng.rules_restart"),
            ask: Ask::ApplyRules(id),
        });
    }

    /// The core as it would be built now, when it differs from the running one in its rules
    /// only: the new plan, the whole new config and the rule list.
    pub(super) fn live_rules_change(&self) -> Option<(Plan, Value)> {
        let live = self.live.as_ref()?;
        let mut plan = live.plan.clone();
        plan.routing = self.config.mode.routing;
        plan.rules = crate::model::rule::effective_rules(
            plan.routing,
            &self.config.rules,
            &self.config.presets.enabled,
            &crate::model::rule::builtin_presets(),
            crate::platform::IS_WINDOWS,
        );
        if let Some(geo) = live
            .binary
            .parent()
            .and_then(crate::xray::geodata::Geo::load)
        {
            crate::xray::geodata::drop_missing(&mut plan.rules, &geo);
        }
        let config = crate::xray::config::build_with(&live.server, &live.core_cfg, &plan).ok()?;
        (without_rules(&config) == without_rules(&live.config)).then_some((plan, config))
    }

    /// Sends the new rule list to the core. `false`: it cannot be done that way (the change
    /// reaches beyond the rules, or there is no API), the caller asks for a restart.
    fn apply_rules_live(&mut self, id: u64) -> bool {
        if self.rules_inflight {
            // One call at a time: the answer to the running one starts the next with the
            // rules as they are by then.
            self.rules_dirty = true;
            return true;
        }
        let Some((plan, config)) = self.live_rules_change() else {
            return false;
        };
        let Some(live) = &self.live else {
            return false;
        };
        let Some(endpoint) = live.core_cfg.api_endpoint.clone() else {
            return false;
        };
        let (api, tx) = (self.rules_api.clone(), self.tx.clone());
        let (binary, dir) = (live.binary.clone(), self.run_dir.clone());
        let rules = rules_of(&config);
        self.rules_inflight = true;
        self.spawn(async move {
            let result = api.replace(&binary, &endpoint, &dir, rules).await;
            let _ = tx.send(BgEvent::RulesApplied {
                id,
                result,
                plan: Box::new(plan),
                config: Box::new(config),
            });
        });
        true
    }

    /// The core answered the rule list.
    pub(super) fn on_rules_applied(
        &mut self,
        id: u64,
        result: Result<(), String>,
        plan: Plan,
        config: Value,
    ) {
        self.rules_inflight = false;
        if self.conn != Conn::Connected(id) || self.live.is_none() {
            return; // the core was replaced or stopped meanwhile: nothing to keep
        }
        match result {
            Ok(()) => {
                if let Some(live) = &mut self.live {
                    live.plan = plan;
                    live.config = config.clone();
                }
                // `run/xray.json` always shows the rules the core runs with.
                let path = self.run_dir.join("xray.json");
                if let Err(e) = crate::xray::process::write_config(&self.run_dir, &path, &config) {
                    self.log(Level::Warning, format!("could not update xray.json: {e}"));
                }
                self.log(Level::Info, "rules applied to the running core");
                // The bypass list of the system proxy follows the direct rules.
                self.sync_proxy();
                if std::mem::take(&mut self.rules_dirty) {
                    // Something changed while the call ran: send the rules as they are now.
                    if !self.apply_rules_live(id) {
                        self.rules_changed_restart(id);
                    }
                } else {
                    self.status(crate::t!("eng.rules_applied"));
                }
            }
            Err(error) => {
                self.rules_dirty = false;
                self.logt(Level::Warning, || {
                    crate::t!("eng.rules_api_failed", error = error)
                });
                self.rules_changed_restart(id);
            }
        }
    }

    /// The API did not do it: the core restarts with the new rules (the same path as a first
    /// connect, so the TUN adapter clean-up and the hint about old connections apply).
    fn rules_changed_restart(&mut self, id: u64) {
        self.connect(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::mock::MockTunHost;
    use crate::test_support::TempDir;
    use tokio::sync::mpsc::unbounded_channel;

    fn engine(tag: &str) -> (Engine, TempDir) {
        let dir = TempDir::new(tag);
        let (tx, _rx) = unbounded_channel();
        let engine = Engine::build(
            tx,
            crate::test_support::config_ru(),
            Some(Storage::new(dir.path())),
            false,
        )
        .with_tun_host(Arc::new(MockTunHost::healthy()));
        (engine, dir)
    }

    #[tokio::test]
    async fn presets_and_rules_toggle_and_persist() {
        let (mut a, _dir) = engine("toggle");
        a.rules_toggle(RuleRef::Preset("discord-only".into()));
        assert!(a
            .config
            .presets
            .enabled
            .contains(&"discord-only".to_string()));
        a.rules_toggle(RuleRef::Preset("discord-only".into()));
        assert!(!a
            .config
            .presets
            .enabled
            .contains(&"discord-only".to_string()));
        a.rules_toggle(RuleRef::Preset("no-such-preset".into()));
        assert!(!a
            .config
            .presets
            .enabled
            .contains(&"no-such-preset".to_string()));

        a.submit_rule(RuleKind::Domain, " Example.COM ".into());
        assert_eq!(a.config.rules[0].value, "example.com");
        a.rules_toggle(RuleRef::Rule(0));
        assert!(!a.config.rules[0].enabled);
        a.rules_delete(0);
        assert!(a.config.rules.is_empty());
        let saved = a.storage.as_ref().unwrap().load().unwrap();
        assert!(saved.rules.is_empty());
    }

    #[tokio::test]
    async fn bad_and_duplicate_rules_are_alerts_not_changes() {
        let (mut a, _dir) = engine("bad");
        a.submit_rule(RuleKind::Ip, "10.0.0.0/33".into());
        a.submit_rule(RuleKind::Domain, "ok.example".into());
        a.submit_rule(RuleKind::Domain, "ok.example".into());
        assert_eq!(a.config.rules.len(), 1);
        // Both refusals are error alerts; their wording is checked in the i18n tests.
        let alerts = a.alerts();
        assert_eq!(alerts.len(), 2);
        assert!(alerts.iter().all(|al| matches!(al, Alert::Error(_))));
    }

    #[tokio::test]
    async fn routing_mode_changes_and_a_live_core_is_offered_a_restart() {
        let (mut a, _dir) = engine("routing");
        a.rules_set_routing(RoutingMode::Include);
        assert_eq!(a.config.mode.routing, RoutingMode::Include);
        assert!(a.alerts().is_empty(), "nothing runs: no question");
    }

    #[tokio::test]
    async fn direct_rules_extend_the_proxy_bypass_list() {
        let (mut a, _dir) = engine("bypass");
        a.config
            .rules
            .push(Rule::new(RuleKind::Domain, "example.com"));
        a.config.presets.enabled.push("games-direct".into());
        let bypass = a.proxy_bypass();
        assert!(bypass.contains(&"localhost".to_string()));
        assert!(bypass.contains(&"*.example.com".to_string()));
        assert!(bypass.contains(&"*.steampowered.com".to_string()));
        a.config.mode.routing = RoutingMode::Include;
        assert_eq!(a.proxy_bypass(), a.config.proxy.bypass);
    }
}
