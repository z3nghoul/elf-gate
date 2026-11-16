use crate::model::rule::{RoutingMode, Rule, TrafficMode};
use crate::model::server::ServerRole;
use crate::model::subscription::SubscriptionInfo;
use crate::platform::{Privileges, ProxySnapshot};
use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
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
    #[error("{}", crate::t!("err.read", path = .path.display(), source = .source))]
    Read { path: PathBuf, source: io::Error },
    #[error("{}", crate::t!("err.write", path = .path.display(), source = .source))]
    Write { path: PathBuf, source: io::Error },
    #[error("{}", crate::t!("err.parse", path = .path.display(), message = .message))]
    Parse { path: PathBuf, message: String },
    #[error("{}", crate::t!("err.serialize", error = .0))]
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
        Self::for_platform(crate::platform::IS_WINDOWS)
    }
}

impl CoreConfig {
    /// The defaults of one platform (tests fix them, whatever runs the tests).
    pub fn for_platform(windows: bool) -> Self {
        Self {
            xray_path: if windows { "xray.exe" } else { "xray" }.to_string(),
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
    /// TUN mode also points the system proxy at the local core (the "mixed" mode): programs
    /// that respect the proxy keep working through the VPN even when the adapter is down.
    pub with_tun: bool,
    pub bypass: Vec<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            set_system_proxy: true,
            with_tun: true,
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
    /// Windows: with administrator rights, keep allow rules for our programs in the firewall.
    pub manage_firewall: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self::for_platform(crate::platform::IS_WINDOWS)
    }
}

impl TunConfig {
    /// The defaults of one platform (tests fix them, whatever runs the tests).
    pub fn for_platform(windows: bool) -> Self {
        Self {
            xray_path: if windows {
                String::new()
            } else {
                "/usr/local/lib/elf-gate/xray".into()
            },
            name: "elfgate0".into(),
            tunnel_dns: "1.1.1.1".into(),
            local_dns: Vec::new(),
            manage_firewall: true,
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
    /// Privacy mode (screenshots, streams): the screens hide addresses, ids, keys and URLs.
    pub privacy_mode: bool,
    /// Interface language: `en`, `ru` or `uk`. English unless chosen; never read from the system.
    pub language: crate::i18n::Lang,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            last_server: None,
            tun_intro_done: false,
            auto_connect: false,
            theme: "dark".into(),
            privacy_mode: false,
            language: crate::i18n::Lang::default(),
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

/// A subscription server hidden by the user (`[[hidden]]`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HiddenServer {
    pub group: String,
    /// See `engine::hide_key`.
    pub key: String,
}

/// `[device]`: how this installation introduces itself to subscription panels.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DeviceConfig {
    /// Generated once (see `net::device`) and kept, so it never changes between runs.
    pub hwid: String,
}

/// Which releases the update notice may mention.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel {
    /// Releases that are not marked as pre-release.
    #[default]
    Stable,
    /// Pre-releases too.
    Test,
}

/// `[updates]`: the notice about a new version (nothing is downloaded).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UpdatesConfig {
    pub check: bool,
    pub channel: UpdateChannel,
    /// The version the user asked not to be reminded about.
    pub skipped: Option<String>,
}

impl Default for UpdatesConfig {
    fn default() -> Self {
        Self {
            check: true,
            channel: UpdateChannel::Stable,
            skipped: None,
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
    pub device: DeviceConfig,
    pub updates: UpdatesConfig,
    pub subscriptions: Vec<SubscriptionConfig>,
    pub servers: Vec<ServerEntry>,
    pub overrides: Vec<ServerOverride>,
    /// Subscription servers the user removed: they stay out of the list when the provider sends
    /// them again, and can be brought back.
    pub hidden: Vec<HiddenServer>,
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
    /// Unix time of the last successful check for a new version.
    pub last_update_check: Option<i64>,
    /// The newest releases from that check: the notice survives a restart without a new request.
    pub releases: Vec<crate::update::Release>,
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
    fix_owner_with(&*crate::platform::privileges(), path);
}

fn fix_owner_with(privileges: &dyn Privileges, path: &Path) {
    let Some(user) = privileges.invoking_user() else {
        return;
    };
    let mut current = Some(path);
    while let Some(p) = current {
        if !p.starts_with(&user.home) || p == user.home {
            break;
        }
        // A link is never handed over: it could point at a file outside the user's tree.
        if !is_symlink(p) {
            let _ = privileges.chown_to_invoking_user(p);
        }
        current = p.parent();
    }
}

/// Same for everything below `dir` (logs are created lazily by the logger).
pub fn fix_owner_tree(dir: &Path) {
    fix_owner_tree_with(&*crate::platform::privileges(), dir);
}

fn fix_owner_tree_with(privileges: &dyn Privileges, dir: &Path) {
    fix_owner_with(privileges, dir);
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = entry.path();
        match fs::symlink_metadata(&p) {
            Ok(m) if m.file_type().is_symlink() => {}
            Ok(m) if m.is_dir() => fix_owner_tree_with(privileges, &p),
            Ok(_) => fix_owner_with(privileges, &p),
            Err(_) => {}
        }
    }
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

/// Creates `dir` (and missing parents) readable by the owner only: the files inside hold links
/// with UUIDs and subscription tokens. An already existing `dir` is tightened too.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

/// Makes everything below `dir` owner-only: directories 0700, files 0600 (existing ones from
/// older versions too). Symbolic links are left alone. No-op on Windows.
pub fn harden_tree(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let set = |p: &Path, mode: u32| {
            let _ = fs::set_permissions(p, fs::Permissions::from_mode(mode));
        };
        set(dir, 0o700);
        for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = entry.path();
            match fs::symlink_metadata(&p) {
                Ok(m) if m.file_type().is_symlink() => {}
                Ok(m) if m.is_dir() => harden_tree(&p),
                // A socket or a pipe keeps its mode: only plain files are touched.
                Ok(m) if m.is_file() => set(&p, 0o600),
                _ => {}
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

/// At start: new files are private (`platform::private_umask`), the state and config
/// directories exist as 0700, and what older versions left there is tightened.
pub fn prepare_private_files() {
    crate::platform::private_umask();
    let _ = create_private_dir(&log_dir());
    harden_tree(&state_dir());
    harden_tree(&config_dir());
}

/// Writes `bytes` to `path` so that only the owner can read them (an existing file is
/// tightened as well). On Windows the user profile already provides this.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes)
    }
}

pub(crate) fn write_atomic(path: &Path, text: &str) -> io::Result<()> {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let parent = path.parent();
    if let Some(parent) = parent {
        create_private_dir(parent)?;
    }
    // Unique per process and call: the interface (under sudo) and the daemon may save at once.
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(
        ".{}-{}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = PathBuf::from(tmp);
    let write = || -> io::Result<()> {
        write_private(&tmp, text.as_bytes())?;
        // The data must be on disk before the rename, or a crash can leave an empty file.
        fs::OpenOptions::new().write(true).open(&tmp)?.sync_all()?;
        fs::rename(&tmp, path)
    };
    if let Err(e) = write() {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    #[cfg(unix)]
    if let Some(parent) = parent {
        let _ = fs::File::open(parent).and_then(|d| d.sync_all());
    }
    fix_owner(path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    #[cfg(unix)]
    struct RecordingPrivileges {
        home: PathBuf,
        chowned: std::sync::Mutex<Vec<PathBuf>>,
    }

    #[cfg(unix)]
    impl Privileges for RecordingPrivileges {
        fn is_elevated(&self) -> bool {
            true
        }
        fn invoking_user(&self) -> Option<crate::platform::InvokingUser> {
            Some(crate::platform::InvokingUser {
                name: "user".into(),
                home: self.home.clone(),
                uid: 1000,
                gid: 1000,
            })
        }
        fn chown_to_invoking_user(
            &self,
            path: &Path,
        ) -> Result<(), crate::platform::PlatformError> {
            self.chowned.lock().unwrap().push(path.to_path_buf());
            Ok(())
        }
        fn relaunch_elevated(&self, _: &[String]) -> Result<(), crate::platform::PlatformError> {
            Ok(())
        }
    }

    #[cfg(unix)]
    #[test]
    fn owner_fix_skips_symlinks() {
        let home = TempDir::new("symlink-home");
        let state = home.join("state");
        let outside = home.join("outside");
        fs::create_dir_all(state.join("logs")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(state.join("logs/real.log"), "x").unwrap();
        fs::write(outside.join("secret"), "x").unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), state.join("logs/file-link")).unwrap();
        std::os::unix::fs::symlink(&outside, state.join("dir-link")).unwrap();

        let privileges = RecordingPrivileges {
            home: home.to_path_buf(),
            chowned: Default::default(),
        };
        fix_owner_tree_with(&privileges, &state);
        let chowned = privileges.chowned.lock().unwrap().clone();
        assert!(chowned.contains(&state.join("logs/real.log")));
        assert!(chowned.iter().all(|p| !p.starts_with(&outside)));
        assert!(!chowned.contains(&state.join("logs/file-link")));
        assert!(!chowned.contains(&state.join("dir-link")));
        let _ = fs::remove_dir_all(home);
    }

    #[cfg(unix)]
    #[test]
    fn hardening_tightens_files_and_directories_but_not_links() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("harden");
        let outside = TempDir::new("harden-outside");
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        fs::create_dir_all(dir.join("logs")).unwrap();
        fs::write(dir.join("check-cache.json"), "{}").unwrap();
        fs::write(dir.join("logs/elf-gated.log.2026-11-16"), "x").unwrap();
        fs::write(outside.join("target"), "x").unwrap();
        std::os::unix::fs::symlink(outside.join("target"), dir.join("link")).unwrap();
        for p in [
            dir.to_path_buf(),
            dir.join("logs"),
            dir.join("check-cache.json"),
            dir.join("logs/elf-gated.log.2026-11-16"),
            outside.join("target"),
        ] {
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        harden_tree(&dir);
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("logs")), 0o700);
        assert_eq!(mode(&dir.join("check-cache.json")), 0o600);
        assert_eq!(mode(&dir.join("logs/elf-gated.log.2026-11-16")), 0o600);
        assert_eq!(
            mode(&outside.join("target")),
            0o755,
            "a link is not followed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn saved_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("private");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        // An older, world-readable file is tightened on the next save.
        let st = Storage::new(dir.path());
        fs::write(dir.join("config.toml"), "").unwrap();
        fs::set_permissions(dir.join("config.toml"), fs::Permissions::from_mode(0o644)).unwrap();
        st.save(&Config::default()).unwrap();
        st.save_subscriptions(&SubscriptionCache::default())
            .unwrap();
        let mode = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(dir.to_path_buf()), 0o700);
        assert_eq!(mode(dir.join("config.toml")), 0o600);
        assert_eq!(mode(st.cache_path()), 0o600);
        let _ = fs::remove_dir_all(dir);
    }

    /// The default TUN interface name is elf-gate's own, never a generic one (xray0, tun0) that
    /// another program may use; a name already in a config stays as it is.
    #[test]
    fn the_default_tun_name_is_ours_and_a_configured_one_is_kept() {
        assert_eq!(TunConfig::default().name, "elfgate0");
        let dir = TempDir::new("tun-name");
        fs::write(dir.join("config.toml"), "[tun]\nname = \"tun0\"\n").unwrap();
        assert_eq!(Storage::new(dir.path()).load().unwrap().tun.name, "tun0");
    }

    #[test]
    fn missing_file_gives_defaults() {
        let st = Storage::new(TempDir::new("missing").path());
        assert_eq!(st.load().unwrap(), Config::default());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = TempDir::new("roundtrip");
        let st = Storage::new(dir.path());
        let mut cfg = Config::default();
        cfg.servers.push(ServerEntry {
            link: "vless://u@h:443#Имя 🚀".into(),
        });
        cfg.core.socks_port = 1234;
        st.save(&cfg).unwrap();
        assert_eq!(st.load().unwrap(), cfg);
        let leftovers = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0, "no temporary file may stay behind");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn partial_file_uses_defaults_for_the_rest() {
        let dir = TempDir::new("partial");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config.toml"), "[core]\nsocks_port = 2000\n").unwrap();
        let cfg = Storage::new(dir.path()).load().unwrap();
        assert_eq!(cfg.core.socks_port, 2000);
        assert_eq!(cfg.core.http_port, 10809);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn broken_file_is_an_error() {
        let dir = TempDir::new("broken");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config.toml"), "this is [not toml").unwrap();
        assert!(matches!(
            Storage::new(dir.path()).load(),
            Err(StorageError::Parse { .. })
        ));
        let _ = fs::remove_dir_all(dir);
    }
}
