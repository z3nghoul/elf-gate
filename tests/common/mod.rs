//! Helpers shared by the integration tests.

use std::path::{Path, PathBuf};

/// The Xray binary the tests run against: `XRAY_PATH` when set (and non-empty), else
/// `bin/xray` in the repository. `None` means "skip".
pub fn xray_bin() -> Option<PathBuf> {
    if let Some(p) = std::env::var("XRAY_PATH").ok().filter(|v| !v.is_empty()) {
        let p = PathBuf::from(p);
        assert!(
            p.is_file(),
            "XRAY_PATH is set but is not a file: {}",
            p.display()
        );
        return Some(p);
    }
    let fallback = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("bin")
        .join(format!("xray{}", std::env::consts::EXE_SUFFIX));
    fallback.is_file().then_some(fallback)
}
