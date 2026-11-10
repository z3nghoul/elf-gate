use directories::ProjectDirs;
use std::path::PathBuf;

/// Directory for application logs (`<state dir>/logs`).
/// Linux: `~/.local/state/elf-gate`; elsewhere falls back to the local data dir.
pub fn log_dir() -> PathBuf {
    match ProjectDirs::from("", "", "elf-gate") {
        Some(d) => d
            .state_dir()
            .unwrap_or_else(|| d.data_local_dir())
            .join("logs"),
        None => PathBuf::from("logs"),
    }
}
