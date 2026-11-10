//! elf-gate: a TUI client for Xray-core. The library holds everything; `elf-gate` (the TUI)
//! and `elf-gated` (the background part that owns the core) are thin binaries over it.

pub mod action;
pub mod app;
pub mod build_info;
pub mod engine;
pub mod event;
pub mod mock;
pub mod model;
pub mod net;
pub mod parser;
pub mod platform;
pub mod proto;
pub mod storage;
pub mod sysproxy;
pub mod tun;
pub mod ui;
pub mod xray;
