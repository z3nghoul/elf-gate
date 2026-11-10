//! Cache of `xray run -test` verdicts, so a subscription with hundreds of servers is not
//! re-checked on every start. The key is a hash of the generated config; the whole cache
//! is dropped when the Xray version changes (a newer Xray may accept or refuse different things).

use super::validate::{self, Verdict};
use crate::model::server::Server;
use crate::platform;
use crate::storage::CoreConfig;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::process::Command;
use tokio::sync::Semaphore;

/// At most this many `xray run -test` processes at the same time.
pub const MAX_PARALLEL_CHECKS: usize = 4;

/// FNV-1a, 64 bit. Not cryptographic (the input is our own generated config, nobody is
/// attacking the cache); it only has to be stable across runs and Rust versions, which
/// `std`'s `DefaultHasher` does not promise.
pub fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// Stable key of a generated config (`serde_json` keeps object keys sorted).
pub fn config_key(cfg: &serde_json::Value) -> String {
    format!("{:016x}", fnv1a(cfg.to_string().as_bytes()))
}

/// Format of the file; an older one is dropped (its refusals had no time stamp).
const FORMAT: u32 = 2;
/// A refusal is remembered for a day at most, whatever the cause.
pub const REFUSAL_TTL_SECS: i64 = 24 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    /// `None`: accepted. `Some(reason)`: Xray refused the config.
    reason: Option<String>,
    /// Unix time the verdict was recorded.
    at: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheFile {
    #[serde(default)]
    format: u32,
    xray_version: String,
    entries: BTreeMap<String, Entry>,
}

fn now() -> i64 {
    crate::model::subscription::unix_now()
}

fn stat_of(p: &Path) -> String {
    match std::fs::metadata(p) {
        Ok(m) => {
            let secs = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            format!("{}:{secs}", m.len())
        }
        Err(_) => "-".into(),
    }
}

/// What a verdict depends on besides the config: the core (path, size, mtime) and its data
/// files (size, mtime). If any of it changes, old verdicts no longer count.
pub fn environment_fingerprint(binary: &Path) -> String {
    let dir = super::process::asset_dir(binary);
    let text = format!(
        "{}|{}|{}|{}",
        binary.display(),
        stat_of(binary),
        stat_of(&dir.join("geoip.dat")),
        stat_of(&dir.join("geosite.dat"))
    );
    format!("{:016x}", fnv1a(text.as_bytes()))
}

#[derive(Debug, Default)]
pub struct CheckCache {
    path: Option<PathBuf>,
    data: CacheFile,
    dirty: bool,
}

impl CheckCache {
    pub fn load(path: Option<PathBuf>) -> Self {
        let data: CacheFile = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| serde_json::from_str(&t).ok())
            .filter(|d: &CacheFile| d.format == FORMAT)
            .unwrap_or(CacheFile {
                format: FORMAT,
                ..CacheFile::default()
            });
        let mut data: CacheFile = data;
        // Entries written by older versions may hold refusals caused by the environment.
        let before = data.entries.len();
        data.entries.retain(|_, v| {
            !v.reason.as_deref().is_some_and(validate::is_environmental)
                && (v.reason.is_none() || now() - v.at <= REFUSAL_TTL_SECS)
        });
        let dirty = data.entries.len() != before;
        Self { path, data, dirty }
    }

    /// Switches to `version`; entries of another version are forgotten.
    pub fn use_version(&mut self, version: &str) {
        if self.data.xray_version != version {
            self.data.xray_version = version.to_string();
            self.data.entries.clear();
            self.dirty = true;
        }
    }

    pub fn lookup(&self, key: &str) -> Option<Verdict> {
        let e = self.data.entries.get(key)?;
        Some(match &e.reason {
            None => Verdict::Accepted,
            // A refusal older than a day is forgotten, whatever caused it.
            Some(_) if now() - e.at > REFUSAL_TTL_SECS => return None,
            Some(reason) => Verdict::Rejected(reason.clone()),
        })
    }

    /// Only Xray's own verdicts are kept; "could not run" says nothing about the config.
    pub fn store(&mut self, key: String, verdict: &Verdict) {
        let value = match verdict {
            Verdict::Accepted => None,
            // A file the core could not see says nothing about the config: do not remember it.
            Verdict::Rejected(reason) if validate::is_environmental(reason) => return,
            Verdict::Rejected(reason) => Some(reason.clone()),
            Verdict::Unavailable(_) => return,
        };
        self.data.entries.insert(
            key,
            Entry {
                reason: value,
                at: now(),
            },
        );
        self.dirty = true;
    }

    #[cfg(test)]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.data.entries.len()
    }

    pub fn flush(&mut self) {
        let Some(path) = &self.path else { return };
        if !self.dirty {
            return;
        }
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(text) = serde_json::to_string(&self.data) {
            let tmp = path.with_extension("json.tmp");
            if std::fs::write(&tmp, text).is_ok() && std::fs::rename(&tmp, path).is_ok() {
                self.dirty = false;
            }
        }
    }
}

/// First line of `xray version`, e.g. `Xray 26.11.9 (Xray, Penetrates Everything.) ...`.
pub async fn xray_version(binary: &Path) -> Option<String> {
    let guard = platform::child_guard();
    let mut cmd = Command::new(binary);
    cmd.arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    guard.prepare(&mut cmd);
    let child = cmd.spawn().ok()?;
    let _ = guard.attach(&child);
    let out = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
}

/// Shared, rate-limited, cached access to `xray run -test`.
pub struct Checker {
    cache: Mutex<CheckCache>,
    versions: Mutex<HashMap<PathBuf, String>>,
    permits: Semaphore,
    unavailable_reported: AtomicBool,
}

impl Checker {
    pub fn new(cache_path: Option<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            cache: Mutex::new(CheckCache::load(cache_path)),
            versions: Mutex::new(HashMap::new()),
            permits: Semaphore::new(MAX_PARALLEL_CHECKS),
            unavailable_reported: AtomicBool::new(false),
        })
    }

    /// `true` once: the caller logs "validation skipped" a single time, not per server.
    pub fn first_unavailable(&self) -> bool {
        !self.unavailable_reported.swap(true, Ordering::Relaxed)
    }

    pub fn flush(&self) {
        self.cache.lock().unwrap().flush();
    }

    pub async fn version_of(&self, binary: &Path) -> Option<String> {
        if let Some(v) = self.versions.lock().unwrap().get(binary) {
            return Some(v.clone());
        }
        let v = xray_version(binary).await?;
        self.versions
            .lock()
            .unwrap()
            .insert(binary.to_path_buf(), v.clone());
        Some(v)
    }

    /// Verdict for a generated config: from the cache when known, else by running Xray.
    pub async fn check_config(
        &self,
        binary: &Path,
        cfg: &serde_json::Value,
        run_dir: &Path,
    ) -> Verdict {
        let Some(version) = self.version_of(binary).await else {
            // No version means no trustworthy key: run without the cache.
            return validate::check_config(binary, cfg, run_dir).await;
        };
        let key = format!("{}-{}", config_key(cfg), environment_fingerprint(binary));
        {
            let mut cache = self.cache.lock().unwrap();
            cache.use_version(&version);
            if let Some(v) = cache.lookup(&key) {
                return v;
            }
        }
        let _permit = self.permits.acquire().await.ok();
        let verdict = validate::check_config(binary, cfg, run_dir).await;
        self.cache.lock().unwrap().store(key, &verdict);
        verdict
    }

    /// Same as `validate::check` (the server on its own, no user rules), cached.
    pub async fn check(&self, core: &CoreConfig, server: &Server, run_dir: &Path) -> Verdict {
        let cfg = match super::config::build(server, core) {
            Ok(c) => c,
            Err(e) => return Verdict::Rejected(e.to_string()),
        };
        match super::process::resolve_binary(&core.xray_path) {
            Ok(binary) => self.check_config(&binary, &cfg, run_dir).await,
            Err(e) => Verdict::Unavailable(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_is_stable_and_depends_on_the_content() {
        let a = json!({"b": 1, "a": [1, 2]});
        let b = json!({"a": [1, 2], "b": 1});
        assert_eq!(config_key(&a), config_key(&b), "key order must not matter");
        assert_ne!(config_key(&a), config_key(&json!({"a": [1, 3], "b": 1})));
        // Pinned value: a change here would silently invalidate every user's cache.
        assert_eq!(fnv1a(b"hello"), 0xa430_d846_80aa_bd0b);
    }

    #[test]
    fn environmental_refusals_found_in_an_old_cache_file_are_dropped_on_load() {
        let dir = std::env::temp_dir().join(format!("elf-gate-cc2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("check-cache.json");
        std::fs::write(
            &path,
            r#"{"format":2,"xray_version":"v","entries":{"a":{"reason":null,"at":1},"b":{"reason":"stat /usr/local/lib/elf-gate/geoip.dat: no such file","at":4102444800},"c":{"reason":"vless without TLS","at":4102444800}}}"#,
        )
        .unwrap();
        let mut c = CheckCache::load(Some(path));
        c.use_version("v");
        assert_eq!(c.lookup("a"), Some(Verdict::Accepted));
        assert_eq!(c.lookup("b"), None, "the stale environment error is gone");
        assert!(c.lookup("c").is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verdicts_roundtrip_and_a_new_version_drops_them() {
        let dir = std::env::temp_dir().join(format!("elf-gate-cc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("check-cache.json");
        let mut c = CheckCache::load(Some(path.clone()));
        c.use_version("Xray 1");
        c.store("k1".into(), &Verdict::Accepted);
        c.store("k2".into(), &Verdict::Rejected("nope".into()));
        c.store("k3".into(), &Verdict::Unavailable("no binary".into()));
        c.flush();

        let mut again = CheckCache::load(Some(path));
        again.use_version("Xray 1");
        assert_eq!(again.lookup("k1"), Some(Verdict::Accepted));
        assert_eq!(again.lookup("k2"), Some(Verdict::Rejected("nope".into())));
        assert_eq!(again.lookup("k3"), None, "'could not run' is never cached");
        again.use_version("Xray 2");
        assert_eq!(again.len(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn refusals_expire_after_a_day_but_acceptances_do_not() {
        let mut c = CheckCache::load(None);
        c.use_version("v");
        c.store("ok".into(), &Verdict::Accepted);
        c.store("no".into(), &Verdict::Rejected("vless without TLS".into()));
        for e in c.data.entries.values_mut() {
            e.at -= REFUSAL_TTL_SECS + 5;
        }
        assert_eq!(c.lookup("ok"), Some(Verdict::Accepted));
        assert_eq!(c.lookup("no"), None);
    }

    #[test]
    fn an_old_format_file_is_dropped() {
        let dir = std::env::temp_dir().join(format!("elf-gate-cc3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.json");
        std::fs::write(&path, r#"{"xray_version":"v","entries":{"a":null}}"#).unwrap();
        let mut c = CheckCache::load(Some(path));
        c.use_version("v");
        assert_eq!(c.lookup("a"), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A stand-in `xray` that counts how often it is asked to test a config.
    #[cfg(unix)]
    fn counting_xray(dir: &Path, verdict_ok: bool) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let counter = dir.join("runs");
        let body = format!(
            "#!/bin/sh\nif [ \"$1\" = version ]; then echo 'Xray 1.0.0 (fake)'; exit 0; fi\necho x >> {}\n{}\n",
            counter.display(),
            if verdict_ok {
                "echo 'Configuration OK.'; exit 0"
            } else {
                "echo 'Failed to start: a > vless without TLS is prohibited'; exit 23"
            }
        );
        let p = dir.join("xray");
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[cfg(unix)]
    fn runs(dir: &Path) -> usize {
        std::fs::read_to_string(dir.join("runs")).map_or(0, |t| t.lines().count())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_changed_core_or_data_file_invalidates_a_cached_refusal() {
        let dir = std::env::temp_dir().join(format!("elf-gate-cc4-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("geoip.dat"), b"geo").unwrap();
        let bin = counting_xray(&dir, false);
        let checker = Checker::new(None);
        let cfg = serde_json::json!({"a": 1});
        let run_dir = dir.join("run");

        let v1 = checker.check_config(&bin, &cfg, &run_dir).await;
        assert!(matches!(v1, Verdict::Rejected(_)), "{v1:?}");
        assert_eq!(runs(&dir), 1);
        checker.check_config(&bin, &cfg, &run_dir).await;
        assert_eq!(runs(&dir), 1, "the refusal came from the cache");

        // The binary changes (a new mtime): the cached refusal is void, xray really runs.
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(120);
        std::fs::File::options()
            .write(true)
            .open(&bin)
            .unwrap()
            .set_modified(later)
            .unwrap();
        checker.check_config(&bin, &cfg, &run_dir).await;
        assert_eq!(runs(&dir), 2, "a changed xray is asked again");

        // So does a changed data file (size).
        std::fs::write(dir.join("geoip.dat"), b"geo-updated").unwrap();
        checker.check_config(&bin, &cfg, &run_dir).await;
        assert_eq!(runs(&dir), 3, "changed geoip.dat is asked again");
        let _ = std::fs::remove_dir_all(dir);
    }
}
