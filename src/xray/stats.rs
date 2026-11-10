//! Traffic statistics from Xray's own API, read by running `xray api statsquery` (the same
//! binary, so no gRPC dependency).

use crate::platform;
use serde_json::Value;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// Cumulative bytes per outbound since the core started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub proxy_up: u64,
    pub proxy_down: u64,
    pub direct_up: u64,
    pub direct_down: u64,
}

/// `{"stat":[{"name":"outbound>>>proxy>>>traffic>>>uplink","value":"123"}, ...]}`; a counter
/// that is still 0 may be missing or have no `value`. With a backup server both
/// `proxy-primary` and `proxy-backup` count as "proxy".
pub fn parse(json: &str) -> Option<Counters> {
    let v: Value = serde_json::from_str(json).ok()?;
    let mut c = Counters::default();
    for item in v.get("stat")?.as_array()? {
        let name = item.get("name")?.as_str()?;
        let value = match item.get("value") {
            Some(Value::String(s)) => s.parse().unwrap_or(0),
            Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
            _ => 0,
        };
        let mut parts = name.split(">>>");
        if parts.next() != Some("outbound") {
            continue;
        }
        let (Some(tag), Some("traffic"), Some(dir)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let slot = match (tag, dir) {
            ("proxy" | "proxy-primary" | "proxy-backup", "uplink") => &mut c.proxy_up,
            ("proxy" | "proxy-primary" | "proxy-backup", "downlink") => &mut c.proxy_down,
            ("direct", "uplink") => &mut c.direct_up,
            ("direct", "downlink") => &mut c.direct_down,
            _ => continue,
        };
        *slot += value;
    }
    Some(c)
}

pub async fn query(binary: &Path, api_port: u16) -> Option<Counters> {
    let guard = platform::child_guard();
    let mut cmd = Command::new(binary);
    cmd.args([
        "api",
        "statsquery",
        &format!("--server=127.0.0.1:{api_port}"),
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .kill_on_drop(true);
    guard.prepare(&mut cmd);
    let child = cmd.spawn().ok()?;
    let _ = guard.attach(&child);
    let out = tokio::time::timeout(Duration::from_secs(3), child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    parse(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_counters_and_tolerates_missing_values() {
        let c = parse(
            r#"{"stat":[
              {"name":"outbound>>>proxy>>>traffic>>>uplink","value":"100"},
              {"name":"outbound>>>proxy>>>traffic>>>downlink","value":"2000"},
              {"name":"outbound>>>direct>>>traffic>>>downlink"},
              {"name":"outbound>>>direct>>>traffic>>>uplink","value":7},
              {"name":"inbound>>>socks-in>>>traffic>>>uplink","value":"9"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(
            c,
            Counters {
                proxy_up: 100,
                proxy_down: 2000,
                direct_up: 7,
                direct_down: 0
            }
        );
        assert_eq!(parse("{}"), None);
        assert_eq!(parse("not json"), None);
    }

    #[test]
    fn primary_and_backup_both_count_as_proxy() {
        let c = parse(
            r#"{"stat":[
              {"name":"outbound>>>proxy-primary>>>traffic>>>uplink","value":"5"},
              {"name":"outbound>>>proxy-backup>>>traffic>>>uplink","value":"6"}]}"#,
        )
        .unwrap();
        assert_eq!(c.proxy_up, 11);
    }
}
