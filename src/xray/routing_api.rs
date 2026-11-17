//! Changing the routing rules of a running core without restarting it. Xray's `RoutingService`
//! (`AddRule` / `RemoveRule`) is reached through the same binary (`xray api adrules`, no gRPC
//! dependency), like the statistics. The new rule list replaces the old one in one call, in the
//! order a full start with the new config would have, so no rule can be seen half applied.

use super::api_endpoint::ApiEndpoint;
use super::config::Plan;
use crate::platform;
use crate::storage::CoreConfig;
use serde_json::{json, Value};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// What the engine remembers about the running core to change its rules later: the config it
/// was started with and what that was built from.
#[derive(Debug, Clone)]
pub struct Live {
    pub server: crate::model::server::Server,
    pub plan: Plan,
    pub core_cfg: CoreConfig,
    pub binary: PathBuf,
    /// The config the core runs with now (`run/xray.json`).
    pub config: Value,
}

/// `routing.rules` of a config.
pub fn rules_of(config: &Value) -> Vec<Value> {
    config["routing"]["rules"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// The config without its rule list. Two configs that are equal in this sense differ only in
/// the rules, so the running core can take the new ones through the API.
pub fn without_rules(config: &Value) -> Value {
    let mut copy = config.clone();
    if let Some(routing) = copy.get_mut("routing").and_then(Value::as_object_mut) {
        routing.remove("rules");
    }
    copy
}

/// The call to the core. A mock stands in for it in tests.
pub trait RulesApi: Send + Sync {
    /// Replaces the rule list of the core behind `api` with `rules`.
    fn replace<'a>(
        &'a self,
        binary: &'a Path,
        api: &'a ApiEndpoint,
        work_dir: &'a Path,
        rules: Vec<Value>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// The real one: `xray api adrules` with a file that holds only the `routing` section.
pub struct CliRulesApi;

impl RulesApi for CliRulesApi {
    fn replace<'a>(
        &'a self,
        binary: &'a Path,
        api: &'a ApiEndpoint,
        work_dir: &'a Path,
        rules: Vec<Value>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let file = work_dir.join("rules-update.json");
            let body = serde_json::to_vec(&json!({ "routing": { "rules": rules } }))
                .map_err(|e| e.to_string())?;
            crate::storage::create_private_dir(work_dir).map_err(|e| e.to_string())?;
            crate::storage::write_private(&file, &body).map_err(|e| e.to_string())?;
            let result = call(binary, api, &file).await;
            let _ = std::fs::remove_file(&file);
            result
        })
    }
}

async fn call(binary: &Path, api: &ApiEndpoint, file: &Path) -> Result<(), String> {
    let guard = platform::child_guard();
    let mut cmd = Command::new(binary);
    cmd.args(["api", "adrules", &format!("--server={}", api.server_arg())])
        .arg(file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    guard.prepare(&mut cmd);
    let child = cmd.spawn().map_err(|e| e.to_string())?;
    let _ = guard.attach(&child);
    let out = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .map_err(|_| "the core did not answer".to_string())?
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        return Ok(());
    }
    let text = format!(
        "{} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // Never a secret in it, but the core may echo a path or an address: the usual filter.
    Err(crate::redact::secrets(text.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_configs_that_differ_only_in_rules_are_equal_without_them() {
        let a = json!({ "outbounds": [1], "routing": { "domainStrategy": "x", "rules": [1, 2] } });
        let b = json!({ "outbounds": [1], "routing": { "domainStrategy": "x", "rules": [3] } });
        let c = json!({ "outbounds": [2], "routing": { "domainStrategy": "x", "rules": [1, 2] } });
        assert_eq!(without_rules(&a), without_rules(&b));
        assert_ne!(without_rules(&a), without_rules(&c));
        assert_eq!(rules_of(&a), vec![json!(1), json!(2)]);
    }
}
