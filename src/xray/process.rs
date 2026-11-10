//! Runs and supervises the Xray core as a child process.

use crate::event::{now_hms, BgEvent, BgTx, Level, LogLine};
use crate::platform::{self, ChildGuard};
use crate::storage::CoreConfig;
use serde_json::Value;
use std::collections::VecDeque;
use std::env;
use std::fmt;
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Instant};

/// How long to wait for the core to start listening.
pub const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
/// Graceful stop budget before the process is killed.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(3);
const TAIL_LINES: usize = 20;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("ядро Xray не найдено: «{0}». Проверьте xray_path в config.toml")]
    BinaryNotFound(String),
    #[error("порт {port} ({what}) уже занят другой программой")]
    PortBusy { port: u16, what: &'static str },
    #[error("не удалось записать конфиг ядра {path}: {source}")]
    WriteConfig { path: PathBuf, source: io::Error },
    #[error("не удалось запустить ядро: {0}")]
    Spawn(String),
    #[error("ядро завершилось сразу после запуска ({code}):\n{tail}")]
    ExitedEarly { code: String, tail: String },
    #[error("ядро не начало слушать порт {port} за {secs} с")]
    NotReady { port: u16, secs: u64 },
}

/// Resolves `xray_path`: a path with directories must be an existing file; a bare
/// name is looked up in `PATH`.
pub fn resolve_binary(xray_path: &str) -> Result<PathBuf, CoreError> {
    let not_found = || CoreError::BinaryNotFound(xray_path.to_string());
    if xray_path.trim().is_empty() {
        return Err(not_found());
    }
    let path = Path::new(xray_path);
    if path.components().count() > 1 || path.is_absolute() {
        return path
            .is_file()
            .then(|| path.to_path_buf())
            .ok_or_else(not_found);
    }
    let name = if xray_path.ends_with(env::consts::EXE_SUFFIX) {
        xray_path.to_string()
    } else {
        format!("{xray_path}{}", env::consts::EXE_SUFFIX)
    };
    env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
        .map(|dir| dir.join(&name))
        .find(|candidate| candidate.is_file())
        .ok_or_else(not_found)
}

/// Checks that the ports the core will bind are free.
pub fn check_ports(core: &CoreConfig) -> Result<(), CoreError> {
    for (port, what) in [(core.socks_port, "socks"), (core.http_port, "http")] {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            return Err(CoreError::PortBusy { port, what });
        }
    }
    Ok(())
}

fn level_of(line: &str) -> Level {
    if line.contains("[Error]") || line.contains("Failed to start") {
        Level::Error
    } else if line.contains("[Warning]") {
        Level::Warning
    } else {
        Level::Info
    }
}

fn spawn_reader<R>(
    stream: R,
    label: &'static str,
    tail: Arc<Mutex<VecDeque<String>>>,
    tx: BgTx,
) -> JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(stream).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }
            {
                let mut t = tail.lock().unwrap();
                if t.len() == TAIL_LINES {
                    t.pop_front();
                }
                t.push_back(line.clone());
            }
            let log = LogLine {
                time: now_hms(),
                level: level_of(&line),
                text: format!("[{label}] {line}"),
            };
            // The receiver is gone only at shutdown.
            let _ = tx.send(BgEvent::Log(log));
        }
    })
}

/// How the core ended.
#[derive(Debug, Clone)]
pub struct ExitInfo {
    pub code: String,
    pub tail: String,
}

fn describe(status: std::process::ExitStatus) -> String {
    match status.code() {
        Some(c) => format!("код {c}"),
        None => "прерван сигналом".to_string(),
    }
}

/// A running Xray process.
pub struct Core {
    child: Child,
    guard: Box<dyn ChildGuard>,
    tail: Arc<Mutex<VecDeque<String>>>,
    readers: Vec<JoinHandle<()>>,
}

impl fmt::Debug for Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Core")
            .field("pid", &self.child.id())
            .finish()
    }
}

impl Core {
    /// Writes the config, starts Xray and waits until the socks port accepts connections.
    /// Output lines go to `log_tx` as `BgEvent::Log`.
    pub async fn start(
        core: &CoreConfig,
        config: &Value,
        run_dir: &Path,
        log_tx: BgTx,
    ) -> Result<Self, CoreError> {
        let binary = resolve_binary(&core.xray_path)?;
        check_ports(core)?;

        let config_path = run_dir.join("xray.json");
        let write = || -> io::Result<()> {
            std::fs::create_dir_all(run_dir)?;
            let text = serde_json::to_vec_pretty(config).map_err(io::Error::other)?;
            std::fs::write(&config_path, text)
        };
        write().map_err(|source| CoreError::WriteConfig {
            path: config_path.clone(),
            source,
        })?;

        let guard = platform::child_guard();
        let mut cmd = Command::new(&binary);
        cmd.arg("run")
            .arg("-c")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Last line of defence: dropping the handle (e.g. while a panic unwinds) kills it.
            .kill_on_drop(true);
        // geoip.dat / geosite.dat are expected next to the binary.
        if let Some(dir) = binary.parent().filter(|d| !d.as_os_str().is_empty()) {
            cmd.env("XRAY_LOCATION_ASSET", dir);
        }
        guard.prepare(&mut cmd);

        let mut child = cmd.spawn().map_err(|e| CoreError::Spawn(e.to_string()))?;
        if let Err(e) = guard.attach(&child) {
            let _ = child.start_kill();
            return Err(CoreError::Spawn(e.to_string()));
        }

        let tail = Arc::new(Mutex::new(VecDeque::new()));
        let mut readers = Vec::new();
        if let Some(out) = child.stdout.take() {
            readers.push(spawn_reader(out, "xray", tail.clone(), log_tx.clone()));
        }
        if let Some(err) = child.stderr.take() {
            readers.push(spawn_reader(err, "xray:err", tail.clone(), log_tx));
        }
        let mut this = Core {
            child,
            guard,
            tail,
            readers,
        };

        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            if this.try_exit().is_some() {
                // Let the readers flush the last lines so the error carries the reason.
                for r in this.readers.drain(..) {
                    let _ = timeout(Duration::from_millis(500), r).await;
                }
                let info = this.try_exit().expect("process already exited");
                return Err(CoreError::ExitedEarly {
                    code: info.code,
                    tail: info.tail,
                });
            }
            if TcpStream::connect(("127.0.0.1", core.socks_port))
                .await
                .is_ok()
            {
                return Ok(this);
            }
            if Instant::now() >= deadline {
                this.stop().await;
                return Err(CoreError::NotReady {
                    port: core.socks_port,
                    secs: STARTUP_TIMEOUT.as_secs(),
                });
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Last output lines of the core, oldest first.
    pub fn tail(&self) -> String {
        self.tail
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// `Some` once the process has exited by itself.
    pub fn try_exit(&mut self) -> Option<ExitInfo> {
        let status = self.child.try_wait().ok().flatten()?;
        Some(ExitInfo {
            code: describe(status),
            tail: self.tail(),
        })
    }

    /// Graceful stop; kills the process if it does not exit within `STOP_TIMEOUT`.
    pub async fn stop(mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            self.guard.terminate(&mut self.child);
            if timeout(STOP_TIMEOUT, self.child.wait()).await.is_err() {
                let _ = self.child.kill().await;
            }
        }
        for r in self.readers.drain(..) {
            r.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_binary_is_reported() {
        for p in ["", "/definitely/not/here/xray", "no-such-xray-binary-xyz"] {
            let err = resolve_binary(p).unwrap_err();
            assert!(matches!(err, CoreError::BinaryNotFound(_)), "{p}");
            assert!(err.to_string().contains("xray_path"));
        }
    }

    #[test]
    fn busy_port_is_reported() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let core = CoreConfig {
            socks_port: port,
            ..CoreConfig::default()
        };
        match check_ports(&core) {
            Err(CoreError::PortBusy { port: p, what }) => {
                assert_eq!(p, port);
                assert_eq!(what, "socks");
            }
            other => panic!("expected PortBusy, got {other:?}"),
        }
        drop(listener);
    }

    #[test]
    fn levels_are_detected() {
        assert_eq!(level_of("2026/01/01 [Warning] core: x"), Level::Warning);
        assert_eq!(level_of("[Error] boom"), Level::Error);
        assert_eq!(level_of("Failed to start: main"), Level::Error);
        assert_eq!(level_of("accepted tcp:1.1.1.1:443"), Level::Info);
    }
}
