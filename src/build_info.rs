//! What differs between a developer (debug) build and a release build handed to testers.

/// Mock servers, fake logs, fake pings and fake traffic exist only to demo the UI.
/// `cfg!` (not `#[cfg]`) keeps the code compiled and linted in every build.
pub const SHOW_MOCK_DATA: bool = cfg!(debug_assertions);

/// The real TUN mode exists (stage 5.2).
pub const TUN_AVAILABLE: bool = true;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Commit the binary was built from; CI sets `ELF_GATE_COMMIT`.
pub fn commit() -> &'static str {
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
