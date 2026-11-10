//! Everything OS-specific lives here, behind traits. `#[cfg]` is allowed only in this module.
//! Stage 1: empty implementations; real ones arrive in stages 3-5.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[cfg(unix)]
mod linux;
#[cfg(windows)]
mod windows;

#[cfg(test)]
pub mod mock;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("not implemented yet")]
    NotImplemented,
    #[error("not supported: {0}")]
    Unsupported(&'static str),
    #[error("{0}")]
    Failed(String),
}

/// Where the local proxy listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAddr {
    pub host: String,
    pub socks_port: u16,
    pub http_port: u16,
}

impl ProxyAddr {
    pub fn http(&self) -> String {
        format!("{}:{}", self.host, self.http_port)
    }
}

/// The system proxy settings of one backend, as a flat key -> value map.
/// A missing key means "the setting did not exist" and is deleted again on restore.
/// Persisted in `state.json` so the user's own settings survive a crash.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxySnapshot {
    pub backend: String,
    pub values: BTreeMap<String, String>,
}

/// Converts Windows-style bypass patterns (`127.*`, `<local>`) to what Linux desktops
/// understand: hosts, domains and CIDR ranges (`127.0.0.0/8`).
pub fn bypass_to_cidr(bypass: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |s: String| {
        if !s.is_empty() && !out.contains(&s) {
            out.push(s);
        }
    };
    for entry in bypass {
        let entry = entry.trim();
        if entry.eq_ignore_ascii_case("<local>") {
            add("localhost".into());
            continue;
        }
        let parts: Vec<&str> = entry.split('.').collect();
        let octets = &parts[..parts.len() - 1];
        let wildcard_ipv4 = parts.last() == Some(&"*")
            && (1..=3).contains(&octets.len())
            && octets.iter().all(|o| o.parse::<u8>().is_ok());
        if wildcard_ipv4 {
            let mut full: Vec<String> = octets.iter().map(|o| o.to_string()).collect();
            full.resize(4, "0".to_string());
            add(format!("{}/{}", full.join("."), 8 * octets.len()));
        } else {
            add(entry.to_string());
        }
    }
    add("localhost".into());
    add("::1".into());
    out
}

pub trait SystemProxy: Send + Sync {
    fn is_supported(&self) -> bool;
    /// Points the system at the local proxy. Does not remember the old settings:
    /// the caller takes `current()` first and persists it.
    fn enable(&self, addr: &ProxyAddr, bypass: &[String]) -> Result<(), PlatformError>;
    /// Restores the settings captured by `current()`.
    fn disable(&self, previous: &ProxySnapshot) -> Result<(), PlatformError>;
    fn current(&self) -> Result<ProxySnapshot, PlatformError>;
}

/// Ties child processes to the application and stops them.
///
/// Usage: `prepare` before spawning, `attach` right after, `terminate` for a
/// graceful stop request (the caller escalates to a kill after a timeout).
pub trait ChildGuard: Send + Sync {
    /// Configures the command: no console window on Windows, death signal on Linux.
    fn prepare(&self, cmd: &mut tokio::process::Command);
    /// Binds the spawned child to the application's lifetime (Windows Job Object).
    fn attach(&self, child: &tokio::process::Child) -> Result<(), PlatformError>;
    /// Asks the child to exit (SIGTERM on Linux, immediate kill on Windows where
    /// a windowless console process has no graceful signal).
    fn terminate(&self, child: &mut tokio::process::Child);
    /// Makes the child leader of its own process group (Linux), so the supervisor and the
    /// core it starts can be found together later. No-op on Windows (Job Object).
    fn own_process_group(&self, cmd: &mut tokio::process::Command);
}

/// The person who started elf-gate through `sudo` (Linux). Config and state then belong to
/// them, not to root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokingUser {
    pub name: String,
    pub home: PathBuf,
    pub uid: u32,
    pub gid: u32,
}

pub trait Privileges: Send + Sync {
    /// root on Linux, an elevated (administrator) token on Windows.
    fn is_elevated(&self) -> bool;
    /// `Some` only when running as root through `sudo`.
    fn invoking_user(&self) -> Option<InvokingUser>;
    /// Gives a file that root created back to the invoking user (no-op otherwise).
    fn chown_to_invoking_user(&self, path: &Path) -> Result<(), PlatformError>;
    /// Windows: starts this program again with administrator rights (UAC prompt) and `args`.
    fn relaunch_elevated(&self, args: &[String]) -> Result<(), PlatformError>;
}

/// The strictest `rp_filter` that applies to the default route's interface (Linux).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpFilter {
    pub interface: String,
    pub value: u8,
}

/// Facts about the machine that decide whether and how TUN mode can run. Everything that
/// touches the OS is here, so the decision logic in `tun` stays testable with a mock.
pub trait TunHost: Send + Sync {
    /// `/dev/net/tun` exists (Linux); always true on Windows.
    fn tun_device_present(&self) -> bool;
    /// Windows: `wintun.dll` is missing next to the core. Never on Linux.
    fn wintun_missing(&self, core_dir: &Path) -> bool;
    /// Linux: the binary is owned by root and nobody else can modify it or its folders.
    /// Anything running with extra privileges must come from such a place.
    fn trusted_binary(&self, path: &Path) -> Result<(), String>;
    /// Can this core create the TUN device? `None` when it cannot be told in advance.
    fn core_can_create_tun(&self, core: &Path) -> Option<bool>;
    /// Linux: the file capabilities of the core as `getcap` prints them (`None`: unknown or not
    /// applicable). Process rules need more than `cap_net_admin` for other users' programs.
    fn core_capabilities(&self, core: &Path) -> Option<String>;
    /// Strict reverse-path filtering breaks "direct" traffic through the tunnel (Linux).
    fn rp_filter(&self) -> Option<RpFilter>;
    /// Upstream resolvers of the system (never loopback stubs).
    fn system_dns(&self) -> Vec<String>;
    fn ipv6_enabled(&self) -> bool;
    fn interface_exists(&self, name: &str) -> bool;
    /// Names of running programs as the core sees them (real file name, no `.exe`).
    fn running_processes(&self) -> Vec<String>;
    /// Stops a core left over from a crashed run, if `pid` is still one of `names`.
    fn kill_stale(&self, pid: u32, names: &[&str]) -> bool;
    /// Capabilities get lost when a parent dies, so a capability-carrying core needs a
    /// supervisor that stops it (Linux, not root).
    fn needs_supervisor(&self) -> bool;
}

/// "Start with the system": a desktop autostart entry (Linux) or a `Run` value (Windows).
pub trait Autostart: Send + Sync {
    fn is_enabled(&self) -> bool;
    /// `command[0]` is the program, the rest its arguments.
    fn enable(&self, command: &[String]) -> Result<(), PlatformError>;
    fn disable(&self) -> Result<(), PlatformError>;
}

/// One command line in the Windows convention: arguments with spaces or quotes are quoted.
pub fn quote_command(command: &[String]) -> String {
    command
        .iter()
        .map(|a| {
            if a.is_empty() || a.contains([' ', '\t', '"']) {
                format!("\"{}\"", a.replace('"', "\\\""))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod command_tests {
    use super::quote_command;

    #[test]
    fn arguments_with_spaces_are_quoted() {
        let c = |v: &[&str]| quote_command(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(c(&["elf-gated.exe"]), "elf-gated.exe");
        assert_eq!(
            c(&["C:\\Program Files\\elf-gate\\elf-gated.exe", "--background"]),
            "\"C:\\Program Files\\elf-gate\\elf-gated.exe\" --background"
        );
        assert_eq!(c(&["a", "b \"c\""]), "a \"b \\\"c\\\"\"");
    }
}

pub trait ShutdownSignals: Send + Sync {
    fn install(&self, on_shutdown: Box<dyn Fn() + Send + Sync>) -> Result<(), PlatformError>;
}

#[cfg(unix)]
use linux as imp;
#[cfg(windows)]
use windows as imp;

pub fn system_proxy() -> Box<dyn SystemProxy> {
    Box::new(imp::proxy::Proxy::detect())
}

pub fn child_guard() -> Box<dyn ChildGuard> {
    Box::new(imp::child::Guard)
}

pub fn privileges() -> Box<dyn Privileges> {
    Box::new(imp::privileges::Elevation)
}

/// What limits this process (Linux: no_new_privs, seccomp, capabilities, mount namespace, LSM
/// label, ids), for the error report when a child cannot see files the parent sees.
pub fn process_restrictions() -> String {
    imp::child::restrictions()
}

/// Entry of the hidden `--supervise` mode (Linux only); the return value is the exit code.
pub fn run_supervisor(args: &[String]) -> i32 {
    #[cfg(unix)]
    {
        linux::supervise::run(args)
    }
    #[cfg(windows)]
    {
        let _ = args;
        eprintln!("--supervise is not used on Windows (a Job Object ties the core to elf-gate)");
        2
    }
}

pub fn autostart() -> Box<dyn Autostart> {
    Box::new(imp::autostart::Entry::detect())
}

pub fn tun_host() -> Box<dyn TunHost> {
    Box::new(imp::tun::Host)
}

pub fn shutdown_signals() -> Box<dyn ShutdownSignals> {
    Box::new(imp::signals::Signals)
}

#[cfg(test)]
mod bypass_tests {
    use super::bypass_to_cidr;

    #[test]
    fn converts_windows_patterns_to_cidr() {
        let input: Vec<String> = [
            "localhost",
            "127.*",
            "10.*",
            "172.16.*",
            "192.168.*",
            "<local>",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            bypass_to_cidr(&input),
            [
                "localhost",
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/16",
                "192.168.0.0/16",
                "::1"
            ]
        );
    }

    #[test]
    fn keeps_hosts_and_domains_and_always_adds_loopback() {
        let out = bypass_to_cidr(&["*.example.com".into(), "intranet".into(), "10.1.2.*".into()]);
        assert!(out.contains(&"*.example.com".to_string()));
        assert!(out.contains(&"intranet".to_string()));
        assert!(out.contains(&"10.1.2.0/24".to_string()));
        assert!(out.contains(&"::1".to_string()) && out.contains(&"localhost".to_string()));
    }
}

// ---------------------------------------------------------------- local IPC

/// A connected local IPC stream (unix socket or named pipe).
pub trait IpcStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> IpcStream for T {}
pub type BoxStream = Box<dyn IpcStream>;

pub type AcceptFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<BoxStream>> + Send + 'a>>;

/// The listening side; owning it is the "one background process per user" lock.
pub trait IpcListener: Send {
    fn accept(&mut self) -> AcceptFuture<'_>;
}

#[derive(Debug, Error)]
pub enum IpcBindError {
    #[error("фоновая часть уже запущена")]
    AlreadyRunning,
    #[error("не удалось создать канал связи: {0}")]
    Other(String),
}

pub fn ipc_bind() -> Result<Box<dyn IpcListener>, IpcBindError> {
    imp::ipc::bind()
}

/// Connects to the running background process.
pub async fn ipc_connect() -> std::io::Result<BoxStream> {
    imp::ipc::connect().await
}

/// Starts a program fully detached: no console window, not tied to our terminal or lifetime.
pub fn spawn_detached(program: &Path, args: &[String]) -> Result<(), PlatformError> {
    imp::ipc::spawn_detached(program, args)
}

// ---------------------------------------------------------------- tray

/// Shows the tray icon and feeds menu choices to `on_action`. `Err` means there is no tray
/// here (no StatusNotifier on Linux, for example): the process works the same without it.
pub async fn tray_start(
    model: tokio::sync::watch::Receiver<crate::tray::TrayModel>,
    on_action: std::sync::Arc<dyn Fn(crate::tray::TrayAction) + Send + Sync>,
) -> Result<(), String> {
    imp::tray::start(model, on_action).await
}

/// Opens the interface in a terminal window (the tray's "open interface").
pub fn open_interface(program: &Path) -> Result<(), PlatformError> {
    imp::tray::open_interface(program)
}
