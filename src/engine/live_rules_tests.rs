//! A change of the rules reaches a running core through its API, as the same rule list a full
//! start with the new rules would have; what the API cannot change restarts the core.

use super::*;
use crate::platform::mock::MockTunHost;
use crate::test_support::TempDir;
use crate::xray::config::build_with;
use crate::xray::routing_api::{rules_of, Live, RulesApi};
use serde_json::Value;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex as StdMutex;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

/// Remembers every rule list it is given.
#[derive(Default)]
struct MockApi {
    calls: StdMutex<Vec<Vec<Value>>>,
    fail: AtomicBool,
}

impl RulesApi for MockApi {
    fn replace<'a>(
        &'a self,
        _binary: &'a std::path::Path,
        _api_port: u16,
        _work_dir: &'a std::path::Path,
        rules: Vec<Value>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(rules);
            if self.fail.load(Ordering::SeqCst) {
                Err("the core said no".into())
            } else {
                Ok(())
            }
        })
    }
}

/// An engine connected to a server, as if its core ran with the config of the moment.
fn connected(dir: &TempDir, mode: Mode) -> (Engine, Arc<MockApi>, UnboundedReceiver<BgEvent>, u64) {
    let (tx, rx) = unbounded_channel();
    let api = Arc::new(MockApi::default());
    let mut e = Engine::build(tx, crate::test_support::config_ru(), None, false)
        .with_tun_host(Arc::new(MockTunHost::healthy()))
        .with_run_dir(dir.path().to_path_buf());
    e.rules_api = api.clone();
    e.add_link("vless://u@10.0.0.5:443?security=none#Real".into());
    let server = e.subs.last().unwrap().servers[0].clone();
    let id = server.id;
    let plan = crate::tun::build_plan(&e.config, &MockTunHost::healthy(), mode, None);
    let config = build_with(&server, &e.config.core, &plan).unwrap();
    e.live = Some(Live {
        server,
        plan,
        core_cfg: e.config.core.clone(),
        binary: PathBuf::from("/definitely/not/here/xray"),
        config,
    });
    e.conn = Conn::Connected(id);
    e.conn_mode = mode;
    e.mode = mode;
    (e, api, rx, id)
}

/// Delivers the answers of the background tasks to the engine.
async fn settle(e: &mut Engine, rx: &mut UnboundedReceiver<BgEvent>) {
    while e.rules_inflight {
        let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the API call never ended")
            .expect("channel open");
        e.on_bg(ev);
    }
}

/// The rule list a full start with the rules of `e.config` would run with.
fn full_start_rules(e: &Engine) -> Vec<Value> {
    let live = e.live.as_ref().unwrap();
    let mut plan = live.plan.clone();
    plan.routing = e.config.mode.routing;
    plan.rules = crate::model::rule::effective_rules(
        plan.routing,
        &e.config.rules,
        &e.config.presets.enabled,
        &crate::model::rule::builtin_presets(),
        crate::platform::IS_WINDOWS,
    );
    rules_of(&build_with(&live.server, &live.core_cfg, &plan).unwrap())
}

#[tokio::test]
async fn a_new_rule_goes_to_the_running_core_as_a_whole_list_and_nothing_restarts() {
    let dir = TempDir::new("live-rule");
    let (mut e, api, mut rx, _id) = connected(&dir, Mode::Proxy);
    let before = rules_of(&e.live.as_ref().unwrap().config);
    e.submit_rule(RuleKind::Domain, "example.com".into());
    assert!(
        e.alerts().is_empty(),
        "no question: the core takes it as it is"
    );
    settle(&mut e, &mut rx).await;
    let calls = api.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_ne!(calls[0], before);
    assert_eq!(calls[0], full_start_rules(&e), "the order of a full start");
    assert!(
        calls[0].iter().any(|r| r["domain"]
            .as_array()
            .is_some_and(|d| d.iter().any(|v| v == "domain:example.com"))),
        "{calls:?}"
    );
    assert!(!e.busy, "the core was not restarted");
    assert!(e.logged("rules applied"));
    // The file the core was started with follows.
    let text = std::fs::read_to_string(dir.path().join("xray.json")).unwrap();
    let on_disk: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(rules_of(&on_disk), calls[0]);
    assert_eq!(rules_of(&e.live.as_ref().unwrap().config), calls[0]);
}

#[tokio::test]
async fn after_a_series_of_switches_the_rules_equal_a_full_recount() {
    let dir = TempDir::new("live-series");
    let (mut e, api, mut rx, _id) = connected(&dir, Mode::Proxy);
    e.submit_rule(RuleKind::Domain, "a.example.com".into());
    settle(&mut e, &mut rx).await;
    e.submit_rule(RuleKind::Ip, "203.0.113.5".into());
    settle(&mut e, &mut rx).await;
    e.rules_toggle(RuleRef::Preset("games-direct".into()));
    settle(&mut e, &mut rx).await;
    e.rules_toggle(RuleRef::Rule(0));
    settle(&mut e, &mut rx).await;
    e.rules_toggle(RuleRef::Preset("games-direct".into()));
    settle(&mut e, &mut rx).await;
    e.rules_delete(1);
    settle(&mut e, &mut rx).await;
    let calls = api.calls.lock().unwrap().clone();
    assert!(calls.len() >= 6, "every change was sent: {}", calls.len());
    assert_eq!(calls.last().unwrap(), &full_start_rules(&e));
    assert_eq!(
        &rules_of(&e.live.as_ref().unwrap().config),
        calls.last().unwrap()
    );
}

#[tokio::test]
async fn changes_made_while_a_call_runs_are_sent_after_it_with_the_rules_of_that_moment() {
    let dir = TempDir::new("live-queue");
    let (mut e, api, mut rx, _id) = connected(&dir, Mode::Proxy);
    e.submit_rule(RuleKind::Domain, "a.example.com".into());
    e.submit_rule(RuleKind::Domain, "b.example.com".into());
    e.submit_rule(RuleKind::Domain, "c.example.com".into());
    settle(&mut e, &mut rx).await;
    let calls = api.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2, "the second call carries both later rules");
    assert_eq!(calls.last().unwrap(), &full_start_rules(&e));
}

#[tokio::test]
async fn an_api_error_restarts_the_core() {
    let dir = TempDir::new("live-fail");
    let (mut e, api, mut rx, id) = connected(&dir, Mode::Proxy);
    api.fail.store(true, Ordering::SeqCst);
    e.submit_rule(RuleKind::Domain, "example.com".into());
    settle(&mut e, &mut rx).await;
    assert_eq!(e.conn, Conn::Connecting(id), "the restart is under way");
    assert!(e.busy);
    assert!(
        e.logged("restarting") || e.logged("перезапускаю"),
        "the log says why"
    );
}

#[tokio::test]
async fn what_the_api_cannot_change_still_asks_for_a_restart() {
    let dir = TempDir::new("live-restart");
    // The mode of routing changes the DNS and the last rule: a restart, as before.
    let (mut e, api, _rx, id) = connected(&dir, Mode::Proxy);
    e.rules_set_routing(crate::model::rule::RoutingMode::Include);
    assert!(api.calls.lock().unwrap().is_empty());
    assert!(
        e.alerts()
            .iter()
            .any(|a| matches!(a, Alert::Ask { ask: Ask::ApplyRules(i), .. } if *i == id)),
        "{:?}",
        e.alerts()
    );
    // In TUN a domain rule changes the DNS section: the core has to restart.
    let (mut e, api, _rx, id) = connected(&dir, Mode::Tun);
    e.submit_rule(RuleKind::Domain, "example.com".into());
    assert!(api.calls.lock().unwrap().is_empty());
    assert!(e
        .alerts()
        .iter()
        .any(|a| matches!(a, Alert::Ask { ask: Ask::ApplyRules(i), .. } if *i == id)));
}

#[tokio::test]
async fn a_server_change_is_not_a_rules_change() {
    // Connecting to another server goes through `connect`: a restart, whatever the rules are.
    let dir = TempDir::new("live-server");
    let (mut e, api, _rx, id) = connected(&dir, Mode::Proxy);
    e.connect(id);
    assert!(e.busy, "a start is under way");
    assert!(api.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn without_a_running_core_a_rule_change_only_saves() {
    let dir = TempDir::new("live-idle");
    let (mut e, api, _rx, _id) = connected(&dir, Mode::Proxy);
    e.conn = Conn::Disconnected;
    e.live = None;
    e.submit_rule(RuleKind::Domain, "example.com".into());
    assert!(api.calls.lock().unwrap().is_empty());
    assert!(e.alerts().is_empty());
}

/// Which presets (and what kinds of rules) can reach a running core through the API in each
/// mode, and which need a restart (they change more than the rule list). The table is the
/// answer to "what restarts": see docs/decisions.md.
#[tokio::test]
async fn the_presets_that_still_need_a_restart_are_the_ones_that_touch_the_dns() {
    let dir = TempDir::new("live-presets");
    let mut table = Vec::new();
    for mode in [Mode::Proxy, Mode::Tun] {
        for preset in crate::model::rule::builtin_presets() {
            let (mut e, _api, _rx, _id) = connected(&dir, mode);
            e.config.presets.enabled.clear();
            e.config.presets.enabled.push(preset.id.clone());
            let live_ok = e.live_rules_change().is_some();
            table.push((mode, preset.id.clone(), live_ok));
        }
    }
    println!("{table:#?}");
    // In proxy mode there is no DNS section to change: every preset goes through the API.
    assert!(table
        .iter()
        .filter(|(m, ..)| *m == Mode::Proxy)
        .all(|(.., ok)| *ok));
    // In TUN the presets that list domains also change the DNS section (names that resolve
    // through the tunnel or locally): the core has to restart for them.
    let mut restart: Vec<&str> = table
        .iter()
        .filter(|(m, _, ok)| *m == Mode::Tun && !ok)
        .map(|(_, id, _)| id.as_str())
        .collect();
    restart.sort_unstable();
    assert_eq!(restart, ["games-direct", "ru-direct", "ua-direct"]);
}
