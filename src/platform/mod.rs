//! Everything OS-specific lives here, behind traits. `#[cfg]` is allowed only in this module.
//! Stage 1: empty implementations; real ones arrive in stages 3-5.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
}

pub trait Privileges: Send + Sync {
    fn is_elevated(&self) -> bool;
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
