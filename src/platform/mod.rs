//! Everything OS-specific lives here, behind traits. `#[cfg]` is allowed only in this module.
//! Stage 1: empty implementations; real ones arrive in stages 3-5.

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
}

pub trait SystemProxy: Send + Sync {
    fn is_supported(&self) -> bool;
    fn enable(&self, addr: &str, bypass: &[String]) -> Result<(), PlatformError>;
    fn disable(&self) -> Result<(), PlatformError>;
    fn current(&self) -> Result<Option<String>, PlatformError>;
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
    Box::new(imp::proxy::Proxy)
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
