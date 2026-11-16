//! Helpers shared by unit tests.

use crate::i18n::Lang;
use crate::storage::Config;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// The default configuration with Russian texts: most unit tests assert on the Russian wording,
/// and the engine and the screen state take their language from the config.
pub fn config_ru() -> Config {
    let mut config = Config::default();
    config.ui.language = Lang::Ru;
    // Screens show these: the tests must not depend on the host (Linux data everywhere).
    config.core = crate::storage::CoreConfig::for_platform(false);
    config.tun = crate::storage::TunConfig::for_platform(false);
    config
}

/// An empty, uniquely named directory in the system temp folder, removed on drop (also while a
/// panic unwinds). The name carries the pid and a counter, so parallel tests never share one.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "elf-gate-test-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl std::ops::Deref for TempDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directories_are_unique_and_removed_on_drop() {
        let a = TempDir::new("same");
        let b = TempDir::new("same");
        assert_ne!(a.path(), b.path());
        assert!(a.is_dir());
        let gone = a.path().to_path_buf();
        drop(a);
        assert!(!gone.exists());
    }
}
