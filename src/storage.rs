use crate::model::rule::{RoutingMode, Rule, TrafficMode};
use crate::model::server::ServerRole;
use crate::model::subscription::SubscriptionInfo;
use crate::platform::ProxySnapshot;
use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

const APP_DIR: &str = "elf-gate";
const CONFIG_FILE: &str = "config.toml";
const STATE_FILE: &str = "state.json";

/// Under `sudo` the config belongs to the user who ran it, not to root.
fn invoking_home() -> Option<PathBuf> {
    crate::platform::privileges()
        .invoking_user()
        .map(|u| u.home)
}

/// Configuration directory: `%APPDATA%\elf-gate` on Windows, `~/.config/elf-gate` on Linux
/// (the invoking user's, when started through `sudo`).
pub fn config_dir() -> PathBuf {
    if let Some(home) = invoking_home() {
        return home.join(".config").join(APP_DIR);
    }
    BaseDirs::new()
        .map(|d| d.config_dir().join(APP_DIR))
        .unwrap_or_else(|| PathBuf::from(APP_DIR))
}

/// State directory (logs, run files): `~/.local/state/elf-gate` on Linux,
/// the same folder as the config on Windows.
pub fn state_dir() -> PathBuf {
    if let Some(home) = invoking_home() {
        return home.join(".local").join("state").join(APP_DIR);
    }
    BaseDirs::new()
        .and_then(|d| d.state_dir().map(|s| s.join(APP_DIR)))
        .unwrap_or_else(config_dir)
}

pub fn log_dir() -> PathBuf {
    state_dir().join("logs")
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("не удалось прочитать {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("не удалось записать {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
    #[error("ошибка в {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("не удалось сериализовать конфигурацию: {0}")]
    Serialize(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CoreConfig {
    pub xray_path: String,
    pub socks_port: u16,
    pub http_port: u16,
    pub api_port: u16,
    pub log_level: String,
    /// Detailed core log: access lines ("accepted ...") and `info` level. Off by default.
    pub verbose_log: bool,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            xray_path: if cfg!(windows) { "xray.exe" } else { "xray" }.to_string(),
            socks_port: 10808,
            http_port: 10809,
            api_port: 10085,
            log_level: "warning".into(),
            verbose_log: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ProxyConfig {
    /// `false`: the system proxy is never touched (programs are configured by hand).
    pub set_system_proxy: bool,
    pub bypass: Vec<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            set_system_proxy: true,
            bypass: [
                "localhost",
                "127.*",
                "10.*",
                "172.16.*",
                "192.168.*",
                "<local>",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ModeConfig {
    pub traffic: TrafficMode,
    pub routing: RoutingMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TunConfig {
    /// Xray used in TUN mode on Linux. It must be a root-owned copy that users cannot modify
    /// (it gets `cap_net_admin`); empty means "same as `core.xray_path`" (Windows).
    pub xray_path: String,
    /// Interface name (Linux limits it to 15 characters).
    pub name: String,
    /// Public resolver that "through the VPN" domains are resolved with, via the tunnel.
    pub tunnel_dns: String,
    /// Upstream resolvers for names that resolve locally; empty = use the system's.
    pub local_dns: Vec<String>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            xray_path: if cfg!(windows) {
                String::new()
            } else {
                "/usr/local/lib/elf-gate/xray".into()
            },
            name: "elfgate0".into(),
            tunnel_dns: "1.1.1.1".into(),
            local_dns: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PresetsConfig {
    pub enabled: Vec<String>,
}

impl Default for PresetsConfig {
    fn default() -> Self {
        Self {
            enabled: vec!["local-direct".into()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UiConfig {
    /// `"<group>/<name>"` of the server connected last (used by `--tun`).
    pub last_server: Option<String>,
    /// The "enable the discord-only preset?" question was asked once.
    pub tun_intro_done: bool,
    /// Connect to `last_server` in the last traffic mode when the program starts. Off by default.
    pub auto_connect: bool,
    /// `dark` or `light`.
    pub theme: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            last_server: None,
            tun_intro_done: false,
            auto_connect: false,
            theme: "dark".into(),
        }
    }
}

/// A server added by hand; stored as its original link.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerEntry {
    pub link: String,
}

/// Per-server settings chosen in the UI, kept apart from the link so re-importing a
/// subscription does not lose them. `server` is `"<group>/<name>|<host>:<port>"`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerOverride {
    pub server: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
    /// `fp` was found by the automatic search, not chosen by hand.
    #[serde(default, skip_serializing_if = "is_false")]
    pub fp_auto: bool,
    /// Xray version the automatic search ran with; it is repeated when the version changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fp_auto_xray: Option<String>,
    /// Split the TLS ClientHello into pieces (Xray `fragment`). Off by default.
    #[serde(default, skip_serializing_if = "is_false")]
    pub fragment: bool,
    /// Role in the "primary + backup" scheme.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<ServerRole>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl ServerOverride {
    pub fn new(server: String) -> Self {
        Self {
            server,
            fp: None,
            fp_auto: false,
            fp_auto_xray: None,
            fragment: false,
            role: None,
        }
    }

    /// Nothing is overridden any more: the entry can be dropped from `config.toml`.
    pub fn is_empty(&self) -> bool {
        self.fp.is_none() && !self.fragment && self.role.is_none() && self.fp_auto_xray.is_none()
    }
}

/// `[ping]`: how the "ping all" command measures a server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PingConfig {
    /// `tcp`: time to open a TCP connection. `url`: a request through a temporary Xray.
    pub mode: PingMode,
    pub url: String,
    pub timeout_ms: u64,
    /// Background TCP ping of all servers every this many seconds; 0 = off.
    pub auto_interval_secs: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PingMode {
    #[default]
    Tcp,
    Url,
}

impl Default for PingConfig {
    fn default() -> Self {
        Self {
            mode: PingMode::Tcp,
            url: "https://www.gstatic.com/generate_204".into(),
            timeout_ms: 3000,
            auto_interval_secs: 60,
        }
    }
}

/// `[[subscriptions]]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SubscriptionConfig {
    pub name: String,
    pub url: String,
    pub user_agent: String,
    /// 0 turns automatic updates off.
    pub auto_update_hours: u32,
}

impl Default for SubscriptionConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            url: String::new(),
            user_agent: crate::net::fetch::DEFAULT_USER_AGENT.into(),
            auto_update_hours: 12,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Config {
    pub core: CoreConfig,
    pub mode: ModeConfig,
    pub proxy: ProxyConfig,
    pub tun: TunConfig,
    pub presets: PresetsConfig,
    pub ui: UiConfig,
    pub ping: PingConfig,
    pub subscriptions: Vec<SubscriptionConfig>,
    pub servers: Vec<ServerEntry>,
    pub overrides: Vec<ServerOverride>,
    pub rules: Vec<Rule>,
}

impl Config {
    /// The copy the interface may see: no server links and no subscription URLs (they carry
    /// keys and tokens). Everything else the screens need stays.
    pub fn redacted(&self) -> Config {
        let mut c = self.clone();
        c.servers.clear();
        for s in &mut c.subscriptions {
            s.url.clear();
        }
        c
    }
}

/// Set while we have changed the system proxy; holds what to put back.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyState {
    pub previous: ProxySnapshot,
    pub address: String,
}

/// Set while a TUN core runs, so a crashed run can be cleaned up at the next start.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunState {
    /// The core process (or its supervisor on Linux).
    pub pid: u32,
    pub interface: String,
}

/// Service state that must survive a crash (`state.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct State {
    pub proxy: Option<ProxyState>,
    pub tun: Option<TunState>,
}

#[derive(Debug, Clone)]
pub struct StateStore {
    path: PathBuf,
}

impl StateStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            path: dir.into().join(STATE_FILE),
        }
    }

    pub fn default_location() -> Self {
        Self::new(state_dir())
    }

    pub fn load(&self) -> Result<State, StorageError> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(State::default()),
            Err(source) => {
                return Err(StorageError::Read {
                    path: self.path.clone(),
                    source,
                })
            }
        };
        serde_json::from_str(&text).map_err(|e| StorageError::Parse {
            path: self.path.clone(),
            message: e.to_string(),
        })
    }

    pub fn save(&self, state: &State) -> Result<(), StorageError> {
        let text = serde_json::to_string_pretty(state)
            .map_err(|e| StorageError::Serialize(e.to_string()))?;
        write_atomic(&self.path, &text).map_err(|source| StorageError::Write {
            path: self.path.clone(),
            source,
        })
    }
}

/// Reads and writes `config.toml` in one directory.
#[derive(Debug, Clone)]
pub struct Storage {
    dir: PathBuf,
}

impl Storage {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn default_location() -> Self {
        Self::new(config_dir())
    }

    pub fn config_path(&self) -> PathBuf {
        self.dir.join(CONFIG_FILE)
    }

    /// A missing file is not an error: defaults are returned.
    pub fn load(&self) -> Result<Config, StorageError> {
        let path = self.config_path();
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(source) => return Err(StorageError::Read { path, source }),
        };
        toml::from_str(&text).map_err(|e| StorageError::Parse {
            path,
            message: e.to_string(),
        })
    }

    /// Writes via a temporary file and a rename, so a crash cannot leave a half-written config.
    pub fn save(&self, config: &Config) -> Result<(), StorageError> {
        let path = self.config_path();
        let text =
            toml::to_string_pretty(config).map_err(|e| StorageError::Serialize(e.to_string()))?;
        write_atomic(&path, &text).map_err(|source| StorageError::Write { path, source })
    }
}

/// Servers of one subscription as of its last successful update.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedSubscription {
    pub links: Vec<String>,
    pub info: Option<SubscriptionInfo>,
    /// Unix time.
    pub updated: Option<i64>,
}

/// `subscriptions.json` next to `config.toml`: what the subscriptions returned last time, so
/// the server list is there at startup and a failed update changes nothing.
pub type SubscriptionCache = std::collections::BTreeMap<String, CachedSubscription>;

impl Storage {
    fn cache_path(&self) -> PathBuf {
        self.dir.join("subscriptions.json")
    }

    pub fn load_subscriptions(&self) -> SubscriptionCache {
        fs::read_to_string(self.cache_path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save_subscriptions(&self, cache: &SubscriptionCache) -> Result<(), StorageError> {
        let path = self.cache_path();
        let text =
            serde_json::to_string(cache).map_err(|e| StorageError::Serialize(e.to_string()))?;
        write_atomic(&path, &text).map_err(|source| StorageError::Write { path, source })
    }
}

/// Gives files that root created under `sudo` back to the invoking user (best effort),
/// walking up to, but not including, their home directory.
pub fn fix_owner(path: &Path) {
    let privileges = crate::platform::privileges();
    let Some(user) = privileges.invoking_user() else {
        return;
    };
    let mut current = Some(path);
    while let Some(p) = current {
        if !p.starts_with(&user.home) || p == user.home {
            break;
        }
        let _ = privileges.chown_to_invoking_user(p);
        current = p.parent();
    }
}

/// Same for everything below `dir` (logs are created lazily by the logger).
pub fn fix_owner_tree(dir: &Path) {
    fix_owner(dir);
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = entry.path();
        if p.is_dir() {
            fix_owner_tree(&p);
        } else {
            fix_owner(&p);
        }
    }
}

fn write_atomic(path: &Path, text: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    fs::write(&tmp, text)?;
    fs::rename(&tmp, path)?;
    fix_owner(path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("elf-gate-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn missing_file_gives_defaults() {
        let st = Storage::new(temp_dir("missing"));
        assert_eq!(st.load().unwrap(), Config::default());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = temp_dir("roundtrip");
        let st = Storage::new(&dir);
        let mut cfg = Config::default();
        cfg.servers.push(ServerEntry {
            link: "vless://u@h:443#Имя 🚀".into(),
        });
        cfg.core.socks_port = 1234;
        st.save(&cfg).unwrap();
        assert_eq!(st.load().unwrap(), cfg);
        assert!(!dir.join("config.toml.tmp").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn partial_file_uses_defaults_for_the_rest() {
        let dir = temp_dir("partial");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config.toml"), "[core]\nsocks_port = 2000\n").unwrap();
        let cfg = Storage::new(&dir).load().unwrap();
        assert_eq!(cfg.core.socks_port, 2000);
        assert_eq!(cfg.core.http_port, 10809);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn broken_file_is_an_error() {
        let dir = temp_dir("broken");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config.toml"), "this is [not toml").unwrap();
        assert!(matches!(
            Storage::new(&dir).load(),
            Err(StorageError::Parse { .. })
        ));
        let _ = fs::remove_dir_all(dir);
    }
}
