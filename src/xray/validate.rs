//! Asks Xray itself whether it accepts the config generated for a server
//! (`xray run -test`). This replaces guessing from address patterns: Xray's own
//! rules (for example which hosts may use unencrypted VLESS) stay Xray's business.

use crate::platform;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

static NO_ASSET_ENV: AtomicBool = AtomicBool::new(false);

/// `xray run -test` only passed WITHOUT the explicit asset variable (see `check_config`): the
/// core is then started the same way.
pub fn asset_env_disabled() -> bool {
    NO_ASSET_ENV.load(Ordering::Relaxed)
}

/// A refusal caused by the environment (a file the core cannot see), not by the config: it says
/// nothing about the server and must not be cached.
pub fn is_environmental(reason: &str) -> bool {
    let r = reason.to_lowercase();
    r.contains("stat ")
        || r.contains("no such file")
        || r.contains("permission denied")
        || r.contains("geoip.dat")
        || r.contains("geosite.dat")
}

/// How the child was started, for the error report: argv, cwd, the variables that matter and
/// the parent's own limits, plus what the PARENT sees of the data files.
pub fn spawn_report(binary: &Path, cfg_file: &Path, with_env: bool) -> String {
    let dir = super::process::asset_dir(binary);
    let seen = |f: &str| match std::fs::metadata(dir.join(f)) {
        Ok(m) => format!("{f}: {} байт", m.len()),
        Err(e) => format!("{f}: {e}"),
    };
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| "-".into());
    format!(
        "argv: {} run -test -c {}; cwd: {}; XRAY_LOCATION_ASSET: {}; PATH: {}; HOME: {}; XDG_RUNTIME_DIR: {}; container/flatpak: {}/{}; родитель видит {} и {}; {}",
        binary.display(),
        cfg_file.display(),
        std::env::current_dir().map_or("?".into(), |d| d.display().to_string()),
        if with_env { dir.display().to_string() } else { "не задан".into() },
        env("PATH"),
        env("HOME"),
        env("XDG_RUNTIME_DIR"),
        env("container"),
        env("FLATPAK_ID"),
        seen("geoip.dat"),
        seen("geosite.dat"),
        platform::process_restrictions()
    )
}

struct Run {
    ok: bool,
    text: String,
}

async fn run_once(binary: &Path, file: &Path, with_env: bool) -> Result<Run, Verdict> {
    let guard = platform::child_guard();
    let mut cmd = Command::new(binary);
    cmd.args(["run", "-test", "-c"])
        .arg(file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let dir = super::process::asset_dir(binary);
    if with_env {
        cmd.env("XRAY_LOCATION_ASSET", &dir);
    } else {
        // The way a shell run works: no variable, the core finds its data next to itself.
        cmd.env_remove("XRAY_LOCATION_ASSET").current_dir(&dir);
    }
    guard.prepare(&mut cmd);
    let child = cmd
        .spawn()
        .map_err(|e| Verdict::Unavailable(format!("не удалось запустить xray: {e}")))?;
    let _ = guard.attach(&child);
    match timeout(CHECK_TIMEOUT, child.wait_with_output()).await {
        Err(_) => Err(Verdict::Unavailable(
            "xray run -test не завершился за 10 с".into(),
        )),
        Ok(Err(e)) => Err(Verdict::Unavailable(format!("ошибка ожидания xray: {e}"))),
        Ok(Ok(out)) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            Ok(Run {
                ok: out.status.success() && text.contains("Configuration OK"),
                text,
            })
        }
    }
}

/// Runs `xray run -test` on any ready-made config (TUN configs included: `-test` does not
/// create the interface, so no privileges are needed).
///
/// If the core refuses because it cannot see a data file, the check is repeated the way a shell
/// would run it (no `XRAY_LOCATION_ASSET`, working directory next to the core). When that
/// passes, the core is started that way too, and the log says so; when it does not, the
/// refusal carries both outputs in full and a report of how the child was started.
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
    let with_env = !asset_env_disabled();
    let verdict = match run_once(binary, &file, with_env).await {
        Err(v) => v,
        Ok(r) if r.ok => Verdict::Accepted,
        Ok(r) => {
            let first = root_cause(&r.text);
            if !is_environmental(&first) {
                Verdict::Rejected(first)
            } else {
                // Retry with the other way of passing the assets.
                match run_once(binary, &file, !with_env).await {
                    Ok(r2) if r2.ok => {
                        NO_ASSET_ENV.store(with_env, Ordering::Relaxed);
                        tracing::warn!(
                            "xray run -test passed only {} XRAY_LOCATION_ASSET; using that way from now on. First output: {}",
                            if with_env { "without" } else { "with" },
                            r.text.trim()
                        );
                        Verdict::Accepted
                    }
                    other => {
                        let second = other
                            .map_or_else(|v| format!("{v:?}"), |r2| r2.text.trim().to_string());
                        let report = spawn_report(binary, &file, with_env);
                        tracing::warn!(
                            "xray run -test refused: {}\n--- retry: {second}\n--- {report}",
                            r.text.trim()
                        );
                        Verdict::Rejected(format!(
                            "{first}\n\nПолный вывод xray:\n{}\n\nПовтор без XRAY_LOCATION_ASSET:\n{second}\n\n{report}",
                            r.text.trim()
                        ))
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
    use crate::storage::CoreConfig;
    use crate::xray::checkcache::Checker;

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
        let v = Checker::new(None)
            .check(&core, &server, &std::env::temp_dir())
            .await;
        assert!(matches!(v, Verdict::Unavailable(_)), "{v:?}");
    }

    #[tokio::test]
    async fn unsupported_server_is_rejected_without_running_xray() {
        let server = parse_link("trojan://p@h:443#t").unwrap();
        let v = Checker::new(None)
            .check(&CoreConfig::default(), &server, &std::env::temp_dir())
            .await;
        assert!(matches!(v, Verdict::Rejected(_)), "{v:?}");
    }

    /// A stand-in "xray" that cannot see its data when the asset variable is set, the way the
    /// bug report describes a core started by the background process.
    #[cfg(unix)]
    fn fake_xray(dir: &Path, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("xray");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_environment_dependent_refusal_is_retried_the_way_a_shell_runs_it() {
        let dir = std::env::temp_dir().join(format!("elf-gate-fakex-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bin = fake_xray(
            &dir,
            r#"if [ -n "$XRAY_LOCATION_ASSET" ]; then echo "Failed to start: x > stat $XRAY_LOCATION_ASSET/geoip.dat: no such file or directory"; exit 23; fi
echo "Configuration OK."; exit 0"#,
        );
        let run_dir = dir.join("run");
        let v = check_config(&bin, &serde_json::json!({}), &run_dir).await;
        assert_eq!(v, Verdict::Accepted, "the second way works, so it is used");
        assert!(asset_env_disabled());
        NO_ASSET_ENV.store(false, Ordering::Relaxed);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_refusal_that_persists_carries_the_full_output_and_a_spawn_report() {
        let dir = std::env::temp_dir().join(format!("elf-gate-fakex2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("geoip.dat"), b"data").unwrap();
        let bin = fake_xray(
            &dir,
            r#"echo "Failed to start: a > b > stat /x/geoip.dat: no such file or directory"; exit 23"#,
        );
        let v = check_config(&bin, &serde_json::json!({}), &dir.join("run")).await;
        let Verdict::Rejected(text) = v else {
            panic!("{v:?}")
        };
        for needle in [
            "stat /x/geoip.dat",
            "Полный вывод xray",
            "argv:",
            "cwd:",
            "XRAY_LOCATION_ASSET:",
            "geoip.dat: 4 байт",
            "NoNewPrivs",
        ] {
            assert!(text.contains(needle), "{needle} missing in: {text}");
        }
        assert!(is_environmental(&text));
        assert!(!asset_env_disabled());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn environmental_refusals_are_not_cached() {
        use crate::xray::checkcache::CheckCache;
        let mut c = CheckCache::load(None);
        c.use_version("v");
        c.store(
            "k1".into(),
            &Verdict::Rejected("stat /x/geoip.dat: no such file".into()),
        );
        c.store("k2".into(), &Verdict::Rejected("vless without TLS".into()));
        assert_eq!(c.lookup("k1"), None);
        assert!(c.lookup("k2").is_some());
    }
}
