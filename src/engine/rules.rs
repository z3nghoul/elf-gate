//! Routing rules and presets: the data side. (The screen, the cursor and the pickers belong
//! to the interface.)

use super::*;
use crate::model::rule::{validate, RoutingMode};

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
        self.rules_changed();
    }

    pub(crate) fn rules_delete(&mut self, i: usize) {
        if i < self.config.rules.len() {
            self.config.rules.remove(i);
            self.rules_changed();
        }
    }

    pub(crate) fn rules_set_routing(&mut self, mode: RoutingMode) {
        if self.config.mode.routing != mode {
            self.config.mode.routing = mode;
            self.rules_changed();
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
        self.rules_changed();
    }

    /// Saves, and offers to restart the core when it is running.
    fn rules_changed(&mut self) {
        self.save_config();
        if let (Conn::Connected(id), Some(_)) = (&self.conn, &self.core) {
            let id = *id;
            self.alert(Alert::Ask {
                text: crate::t!("eng.rules_restart"),
                ask: Ask::ApplyRules(id),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::mock::MockTunHost;
    use tokio::sync::mpsc::unbounded_channel;

    fn engine(tag: &str) -> Engine {
        let dir = std::env::temp_dir().join(format!("elf-gate-rules-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (tx, _rx) = unbounded_channel();
        Engine::build(tx, Config::default(), Some(Storage::new(dir)), false)
            .with_tun_host(Arc::new(MockTunHost::healthy()))
    }

    #[tokio::test]
    async fn presets_and_rules_toggle_and_persist() {
        let mut a = engine("toggle");
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
        let mut a = engine("bad");
        a.submit_rule(RuleKind::Ip, "10.0.0.0/33".into());
        a.submit_rule(RuleKind::Domain, "ok.example".into());
        a.submit_rule(RuleKind::Domain, "ok.example".into());
        assert_eq!(a.config.rules.len(), 1);
        let alerts = a.alerts();
        assert!(matches!(&alerts[0], Alert::Error(t) if t.contains("префикса")));
        assert!(matches!(&alerts[1], Alert::Error(t) if t.contains("уже есть")));
    }

    #[tokio::test]
    async fn routing_mode_changes_and_a_live_core_is_offered_a_restart() {
        let mut a = engine("routing");
        a.rules_set_routing(RoutingMode::Include);
        assert_eq!(a.config.mode.routing, RoutingMode::Include);
        assert!(a.alerts().is_empty(), "nothing runs: no question");
    }

    #[tokio::test]
    async fn direct_rules_extend_the_proxy_bypass_list() {
        let mut a = engine("bypass");
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
