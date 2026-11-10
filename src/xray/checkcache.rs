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

#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheFile {
    xray_version: String,
    /// `None`: accepted. `Some(reason)`: Xray refused the config.
    entries: BTreeMap<String, Option<String>>,
}

#[derive(Debug, Default)]
pub struct CheckCache {
    path: Option<PathBuf>,
    data: CacheFile,
    dirty: bool,
}

impl CheckCache {
    pub fn load(path: Option<PathBuf>) -> Self {
        let data = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        let mut data: CacheFile = data;
        // Entries written by older versions may hold refusals caused by the environment.
        let before = data.entries.len();
        data.entries
            .retain(|_, v| !v.as_deref().is_some_and(validate::is_environmental));
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
        self.data.entries.get(key).map(|v| match v {
            None => Verdict::Accepted,
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
        self.data.entries.insert(key, value);
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
        let key = config_key(cfg);
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
            r#"{"xray_version":"v","entries":{"a":null,"b":"stat /usr/local/lib/elf-gate/geoip.dat: no such file","c":"vless without TLS"}}"#,
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
}
