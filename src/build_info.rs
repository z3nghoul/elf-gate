//! What differs between a developer (debug) build and a release build handed to testers.
//! Every "not for production" switch is here: a developer build is the only place they work,
//! and `cfg!` (not `#[cfg]`) keeps the code compiled and linted in every build.

/// A developer (debug) build.
pub const DEBUG_BUILD: bool = cfg!(debug_assertions);

/// Mock servers, fake logs, fake pings and fake traffic exist only to demo the UI.
pub const SHOW_MOCK_DATA: bool = DEBUG_BUILD;

/// Demo servers and fake numbers: only in a debug build started with `ELF_GATE_DEMO=1`.
/// (The background process is the one that owns data, so the demo data live there.)
pub fn demo_data() -> bool {
    SHOW_MOCK_DATA && std::env::var_os("ELF_GATE_DEMO").is_some()
}

/// Lab hook: inside a user namespace the real root is unmapped, so "the TUN core belongs to
/// root" cannot hold. Debug builds started with `ELF_GATE_LAB_TRUST_ALL` skip that check.
pub fn lab_trust_all() -> bool {
    DEBUG_BUILD && std::env::var_os("ELF_GATE_LAB_TRUST_ALL").is_some()
}

/// F12 in a debug build: panics on purpose, to see how the terminal is restored.
pub const DEBUG_PANIC_KEY: bool = DEBUG_BUILD;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Commit the binary was built from: CI sets `ELF_GATE_COMMIT`, a local build gets the short
/// hash from git (`build.rs`), and without git it is `dev`.
pub fn commit() -> &'static str {
    // Snapshots of the screens show the commit: tests must not depend on the checkout.
    if cfg!(test) {
        return "dev";
    }
    option_env!("ELF_GATE_COMMIT").unwrap_or("dev")
}

pub fn version_line() -> String {
    let short: String = commit().chars().take(7).collect();
    let kind = if SHOW_MOCK_DATA { "debug" } else { "release" };
    format!("elf-gate {VERSION} (commit {short}, {kind})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_line_mentions_version_and_build_kind() {
        let line = version_line();
        assert!(line.starts_with("elf-gate "));
        assert!(line.contains(VERSION));
        assert!(line.contains("debug") || line.contains("release"));
    }
}
