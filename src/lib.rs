//! elf-gate: a TUI client for Xray-core. The library holds everything; `elf-gate` (the TUI)
//! and `elf-gated` (the background part that owns the core) are thin binaries over it.

pub mod action;
pub mod app;
pub mod autostart;
pub mod build_info;
pub mod daemon;
pub mod engine;
pub mod event;
pub mod firewall;
pub mod i18n;
pub mod ipc;
pub mod mock;
pub mod model;
pub mod net;
pub mod parser;
pub mod platform;
pub mod proto;
pub mod redact;
pub mod storage;
pub mod sync;
pub mod sysproxy;
#[cfg(test)]
pub mod test_support;
#[doc(hidden)]
pub mod testing;
pub mod tray;
pub mod tun;
pub mod ui;
pub mod xray;
