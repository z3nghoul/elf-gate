use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

const APP_DIR: &str = "elf-gate";
const CONFIG_FILE: &str = "config.toml";

/// Configuration directory: `%APPDATA%\elf-gate` on Windows, `~/.config/elf-gate` on Linux.
pub fn config_dir() -> PathBuf {
    BaseDirs::new()
        .map(|d| d.config_dir().join(APP_DIR))
        .unwrap_or_else(|| PathBuf::from(APP_DIR))
}

/// State directory (logs, run files): `~/.local/state/elf-gate` on Linux,
/// the same folder as the config on Windows.
pub fn state_dir() -> PathBuf {
    BaseDirs::new()
        .and_then(|d| d.state_dir().map(|s| s.join(APP_DIR)))
        .unwrap_or_else(config_dir)
}

pub fn log_dir() -> PathBuf {
    state_dir().join("logs")
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("не удалось прочитать {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("не удалось записать {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
    #[error("ошибка в {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("не удалось сериализовать конфигурацию: {0}")]
    Serialize(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CoreConfig {
    pub xray_path: String,
    pub socks_port: u16,
    pub http_port: u16,
    pub api_port: u16,
    pub log_level: String,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            xray_path: if cfg!(windows) { "xray.exe" } else { "xray" }.to_string(),
            socks_port: 10808,
            http_port: 10809,
            api_port: 10085,
            log_level: "warning".into(),
        }
    }
}

/// A server added by hand; stored as its original link.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerEntry {
    pub link: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Config {
    pub core: CoreConfig,
    pub servers: Vec<ServerEntry>,
}

/// Reads and writes `config.toml` in one directory.
#[derive(Debug, Clone)]
pub struct Storage {
    dir: PathBuf,
}

impl Storage {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn default_location() -> Self {
        Self::new(config_dir())
    }

    pub fn config_path(&self) -> PathBuf {
        self.dir.join(CONFIG_FILE)
    }

    /// A missing file is not an error: defaults are returned.
    pub fn load(&self) -> Result<Config, StorageError> {
        let path = self.config_path();
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(source) => return Err(StorageError::Read { path, source }),
        };
        toml::from_str(&text).map_err(|e| StorageError::Parse {
            path,
            message: e.to_string(),
        })
    }

    /// Writes via a temporary file and a rename, so a crash cannot leave a half-written config.
    pub fn save(&self, config: &Config) -> Result<(), StorageError> {
        let path = self.config_path();
        let text =
            toml::to_string_pretty(config).map_err(|e| StorageError::Serialize(e.to_string()))?;
        write_atomic(&path, &text).map_err(|source| StorageError::Write { path, source })
    }
}

fn write_atomic(path: &Path, text: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("toml.tmp");
    fs::write(&tmp, text)?;
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("elf-gate-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn missing_file_gives_defaults() {
        let st = Storage::new(temp_dir("missing"));
        assert_eq!(st.load().unwrap(), Config::default());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = temp_dir("roundtrip");
        let st = Storage::new(&dir);
        let mut cfg = Config::default();
        cfg.servers.push(ServerEntry {
            link: "vless://u@h:443#Имя 🚀".into(),
        });
        cfg.core.socks_port = 1234;
        st.save(&cfg).unwrap();
        assert_eq!(st.load().unwrap(), cfg);
        assert!(!dir.join("config.toml.tmp").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn partial_file_uses_defaults_for_the_rest() {
        let dir = temp_dir("partial");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config.toml"), "[core]\nsocks_port = 2000\n").unwrap();
        let cfg = Storage::new(&dir).load().unwrap();
        assert_eq!(cfg.core.socks_port, 2000);
        assert_eq!(cfg.core.http_port, 10809);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn broken_file_is_an_error() {
        let dir = temp_dir("broken");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config.toml"), "this is [not toml").unwrap();
        assert!(matches!(
            Storage::new(&dir).load(),
            Err(StorageError::Parse { .. })
        ));
        let _ = fs::remove_dir_all(dir);
    }
}
