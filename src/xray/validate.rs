//! Asks Xray itself whether it accepts the config generated for a server
//! (`xray run -test`). This replaces guessing from address patterns: Xray's own
//! rules (for example which hosts may use unencrypted VLESS) stay Xray's business.

use super::config;
use super::process::resolve_binary;
use crate::model::server::Server;
use crate::platform;
use crate::storage::CoreConfig;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

const CHECK_TIMEOUT: Duration = Duration::from_secs(10);
static COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    /// Xray refused the config; the text is Xray's own error.
    Rejected(String),
    /// Could not ask Xray (binary missing, timeout, ...). Not a verdict on the server.
    Unavailable(String),
}

/// Reduces Xray's nested error (`a > b > infra/conf: reason`) to its root cause.
pub fn root_cause(output: &str) -> String {
    let failure = output
        .lines()
        .rev()
        .find(|l| l.contains("Failed to start"))
        .or_else(|| output.lines().rev().find(|l| !l.trim().is_empty()))
        .unwrap_or("unknown error");
    let after = failure
        .split_once("Failed to start:")
        .map_or(failure, |(_, rest)| rest);
    let last = after.rsplit(" > ").next().unwrap_or(after).trim();
    last.strip_prefix("infra/conf:")
        .unwrap_or(last)
        .trim()
        .to_string()
}

/// Generates the server's plain proxy config and runs `xray run -test` on it.
pub async fn check(core: &CoreConfig, server: &Server, run_dir: &Path) -> Verdict {
    let cfg = match config::build(server, core) {
        Ok(c) => c,
        Err(e) => return Verdict::Rejected(e.to_string()),
    };
    let binary = match resolve_binary(&core.xray_path) {
        Ok(b) => b,
        Err(e) => return Verdict::Unavailable(e.to_string()),
    };
    check_config(&binary, &cfg, run_dir).await
}

/// Runs `xray run -test` on any ready-made config (TUN configs included: `-test` does not
/// create the interface, so no privileges are needed).
pub async fn check_config(binary: &Path, cfg: &serde_json::Value, run_dir: &Path) -> Verdict {
    let file = run_dir.join(format!(
        "check-{}-{}.json",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let write = || -> std::io::Result<()> {
        std::fs::create_dir_all(run_dir)?;
        std::fs::write(
            &file,
            serde_json::to_vec_pretty(cfg).map_err(std::io::Error::other)?,
        )
    };
    if let Err(e) = write() {
        return Verdict::Unavailable(format!("не удалось записать {}: {e}", file.display()));
    }

    let guard = platform::child_guard();
    let mut cmd = Command::new(binary);
    cmd.args(["run", "-test", "-c"])
        .arg(&file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(dir) = binary.parent().filter(|d| !d.as_os_str().is_empty()) {
        cmd.env("XRAY_LOCATION_ASSET", dir);
    }
    guard.prepare(&mut cmd);

    let verdict = match cmd.spawn() {
        Err(e) => Verdict::Unavailable(format!("не удалось запустить xray: {e}")),
        Ok(child) => {
            let _ = guard.attach(&child);
            match timeout(CHECK_TIMEOUT, child.wait_with_output()).await {
                Err(_) => Verdict::Unavailable("xray run -test не завершился за 10 с".into()),
                Ok(Err(e)) => Verdict::Unavailable(format!("ошибка ожидания xray: {e}")),
                Ok(Ok(out)) => {
                    let text = format!(
                        "{}{}",
                        String::from_utf8_lossy(&out.stdout),
                        String::from_utf8_lossy(&out.stderr)
                    );
                    if out.status.success() && text.contains("Configuration OK") {
                        Verdict::Accepted
                    } else {
                        Verdict::Rejected(root_cause(&text))
                    }
                }
            }
        }
    };
    let _ = std::fs::remove_file(&file);
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_link;

    #[test]
    fn extracts_root_cause_from_nested_xray_error() {
        let out = "Xray 26.11.9 (Xray, Penetrates Everything.)\n\
            2026/11/10 [Info] infra/conf/serial: Reading config: x\n\
            Failed to start: main: failed to load config files: [/tmp/a.json] > infra/conf: failed to build outbound config with tag proxy > infra/conf: vless without TLS or other encryption is prohibited unless the server address is a private IP or domain\n";
        assert_eq!(
            root_cause(out),
            "vless without TLS or other encryption is prohibited unless the server address is a private IP or domain"
        );
        assert_eq!(root_cause("boom\n"), "boom");
        assert_eq!(root_cause(""), "unknown error");
    }

    #[tokio::test]
    async fn missing_binary_is_unavailable_not_rejected() {
        let server = parse_link(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@h.example.com:443?security=tls#x",
        )
        .unwrap();
        let core = CoreConfig {
            xray_path: "/definitely/not/here/xray".into(),
            ..CoreConfig::default()
        };
        let v = check(&core, &server, &std::env::temp_dir()).await;
        assert!(matches!(v, Verdict::Unavailable(_)), "{v:?}");
    }

    #[tokio::test]
    async fn unsupported_server_is_rejected_without_running_xray() {
        let server = parse_link("trojan://p@h:443#t").unwrap();
        let v = check(&CoreConfig::default(), &server, &std::env::temp_dir()).await;
        assert!(matches!(v, Verdict::Rejected(_)), "{v:?}");
    }
}
