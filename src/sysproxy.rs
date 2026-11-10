//! Switching the system proxy on and off without ever losing the user's own settings.
//!
//! Safety rules:
//! * the previous settings are written to `state.json` *before* anything is changed;
//! * restoring reads `state.json`, so it works from anywhere: normal exit, a panic hook,
//!   a signal handler, or the next start after a crash (`kill -9`, power loss);
//! * if the user had their own proxy, exactly that is put back.

use crate::event::{BgEvent, BgTx};
use crate::platform::{PlatformError, ProxyAddr, SystemProxy};
use crate::storage::{ProxyState, State, StateStore, StorageError};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("системный прокси не поддерживается в этом окружении")]
    Unsupported,
    #[error("приложение завершается")]
    Closed,
    #[error("{0}")]
    Platform(#[from] PlatformError),
    #[error("{0}")]
    State(#[from] StorageError),
}

pub struct ProxyController {
    backend: Box<dyn SystemProxy>,
    store: StateStore,
    /// Serialises enable / restore, which may come from several threads.
    lock: Mutex<()>,
    closed: AtomicBool,
}

impl ProxyController {
    pub fn new(backend: Box<dyn SystemProxy>, store: StateStore) -> Self {
        Self {
            backend,
            store,
            lock: Mutex::new(()),
            closed: AtomicBool::new(false),
        }
    }

    pub fn is_supported(&self) -> bool {
        self.backend.is_supported()
    }

    /// True while `state.json` says we have changed the system proxy.
    #[cfg(test)]
    pub fn is_active(&self) -> bool {
        self.store
            .load()
            .map(|s| s.proxy.is_some())
            .unwrap_or(false)
    }

    pub fn enable(&self, addr: &ProxyAddr, bypass: &[String]) -> Result<(), ProxyError> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.load(Ordering::SeqCst) {
            return Err(ProxyError::Closed);
        }
        if !self.backend.is_supported() {
            return Err(ProxyError::Unsupported);
        }
        let mut state = self.store.load()?;
        let first_time = state.proxy.is_none();
        match &mut state.proxy {
            // Already enabled (or left over from a crash): keep the *original* settings.
            Some(p) => p.address = addr.http(),
            None => {
                state.proxy = Some(ProxyState {
                    previous: self.backend.current()?,
                    address: addr.http(),
                })
            }
        }
        // Persist before touching the system, so a crash right now is recoverable.
        self.store.save(&state)?;

        if let Err(e) = self.backend.enable(addr, bypass) {
            if first_time {
                // Undo a half-applied change and forget it.
                if let Some(p) = state.proxy.take() {
                    let _ = self.backend.disable(&p.previous);
                }
                let _ = self.store.save(&State::default());
            }
            return Err(e.into());
        }
        Ok(())
    }

    /// Restores the user's settings. `Ok(false)` if there was nothing to restore.
    pub fn disable(&self) -> Result<bool, ProxyError> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.restore_locked()
    }

    fn restore_locked(&self) -> Result<bool, ProxyError> {
        let mut state = self.store.load()?;
        let Some(p) = state.proxy.take() else {
            return Ok(false);
        };
        // On failure state.json keeps the snapshot, so the next start can try again.
        self.backend.disable(&p.previous)?;
        self.store.save(&state)?;
        Ok(true)
    }

    /// Startup recovery after a crash. Returns a note for the log if it restored something.
    pub fn recover(&self) -> Result<Option<String>, ProxyError> {
        let addr = self.store.load()?.proxy.map(|p| p.address);
        match (addr, self.disable()?) {
            (Some(addr), true) => Ok(Some(format!(
                "восстановлены прежние настройки системного прокси (после сбоя оставался {addr})"
            ))),
            _ => Ok(None),
        }
    }

    /// Final restore for exit paths that must not fail or hang (panic hook, signals).
    /// Refuses further `enable` calls.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(2);
        let guard = loop {
            match self.lock.try_lock() {
                Ok(g) => break Some(g),
                Err(std::sync::TryLockError::Poisoned(e)) => break Some(e.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                // Someone (maybe this very thread) still holds the lock: go on without it.
                Err(std::sync::TryLockError::WouldBlock) => break None,
            }
        };
        let _ = self.restore_locked();
        drop(guard);
    }
}

static GLOBAL: OnceLock<Arc<ProxyController>> = OnceLock::new();

/// Registers the controller for the panic hook and signal handlers.
pub fn set_global(controller: Arc<ProxyController>) {
    let _ = GLOBAL.set(controller);
}

/// Restores the system proxy from wherever it is called; a no-op if nothing was changed.
pub fn emergency_restore() {
    if let Some(c) = GLOBAL.get() {
        c.close();
    }
}

pub enum ProxyCmd {
    Enable {
        addr: ProxyAddr,
        bypass: Vec<String>,
    },
    Disable,
}

/// Runs proxy commands on one dedicated thread: they take tens of milliseconds
/// (external tools, registry), must not block the UI, and must stay in order.
pub struct ProxyHandle {
    pub controller: Arc<ProxyController>,
    tx: mpsc::Sender<ProxyCmd>,
}

impl ProxyHandle {
    pub fn spawn(controller: Arc<ProxyController>, events: BgTx) -> Self {
        let (tx, rx) = mpsc::channel::<ProxyCmd>();
        let ctrl = controller.clone();
        std::thread::spawn(move || {
            for cmd in rx {
                let ev = match cmd {
                    ProxyCmd::Enable { addr, bypass } => match ctrl.enable(&addr, &bypass) {
                        Ok(()) => BgEvent::ProxyChanged {
                            active: true,
                            error: None,
                        },
                        Err(e) => BgEvent::ProxyChanged {
                            active: false,
                            error: Some(e.to_string()),
                        },
                    },
                    ProxyCmd::Disable => BgEvent::ProxyChanged {
                        active: false,
                        error: ctrl.disable().err().map(|e| e.to_string()),
                    },
                };
                if events.send(ev).is_err() {
                    break;
                }
            }
        });
        Self { controller, tx }
    }

    pub fn send(&self, cmd: ProxyCmd) {
        let _ = self.tx.send(cmd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::mock::{MockProxy, SharedMock};
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("elf-gate-proxy-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn addr() -> ProxyAddr {
        ProxyAddr {
            host: "127.0.0.1".into(),
            socks_port: 10808,
            http_port: 10809,
        }
    }

    fn setup(tag: &str, user: &[(&str, &str)]) -> (Arc<MockProxy>, ProxyController, PathBuf) {
        let dir = temp_dir(tag);
        let mock = Arc::new(MockProxy::with_user_settings(user));
        let ctrl = ProxyController::new(Box::new(SharedMock(mock.clone())), StateStore::new(&dir));
        (mock, ctrl, dir)
    }

    #[test]
    fn enable_then_disable_restores_the_users_own_proxy() {
        let user = [
            ("enabled", "1"),
            ("server", "corp-proxy:3128"),
            ("bypass", "*.corp"),
        ];
        let (mock, ctrl, dir) = setup("own", &user);
        let before = mock.snapshot();

        ctrl.enable(&addr(), &["localhost".into(), "10.*".into()])
            .unwrap();
        assert_eq!(mock.snapshot().values["server"], "127.0.0.1:10809");
        assert!(ctrl.is_active());

        assert!(ctrl.disable().unwrap());
        assert_eq!(
            mock.snapshot(),
            before,
            "user settings must come back exactly"
        );
        assert!(!ctrl.is_active());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn disable_without_enable_does_nothing() {
        let (mock, ctrl, dir) = setup("noop", &[("enabled", "0")]);
        let before = mock.snapshot();
        assert!(!ctrl.disable().unwrap());
        assert_eq!(mock.snapshot(), before);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn second_enable_keeps_the_original_settings() {
        let (mock, ctrl, dir) = setup("twice", &[("server", "orig:1")]);
        let before = mock.snapshot();
        ctrl.enable(&addr(), &[]).unwrap();
        ctrl.enable(&addr(), &[]).unwrap(); // e.g. after a server switch
        ctrl.disable().unwrap();
        assert_eq!(mock.snapshot(), before);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn crash_recovery_restores_from_state_file() {
        let user = [("server", "orig:1"), ("enabled", "1")];
        let (mock, ctrl, dir) = setup("crash", &user);
        let before = mock.snapshot();
        ctrl.enable(&addr(), &[]).unwrap();
        drop(ctrl); // the process "dies": nothing was restored

        // A new process starts with a fresh controller over the same state dir.
        let ctrl2 = ProxyController::new(Box::new(SharedMock(mock.clone())), StateStore::new(&dir));
        let note = ctrl2.recover().unwrap().expect("must report the recovery");
        assert!(note.contains("127.0.0.1:10809"), "{note}");
        assert_eq!(mock.snapshot(), before);
        assert_eq!(ctrl2.recover().unwrap(), None, "second recovery is a no-op");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_enable_rolls_back() {
        let (mock, ctrl, dir) = setup("fail", &[("server", "orig:1")]);
        let before = mock.snapshot();
        mock.fail_enable.store(true, Ordering::SeqCst);
        assert!(ctrl.enable(&addr(), &[]).is_err());
        assert_eq!(
            mock.snapshot(),
            before,
            "half-applied change must be undone"
        );
        assert!(!ctrl.is_active());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_restore_keeps_the_snapshot_for_next_start() {
        let (mock, ctrl, dir) = setup("failrestore", &[("server", "orig:1")]);
        let before = mock.snapshot();
        ctrl.enable(&addr(), &[]).unwrap();
        mock.fail_disable.store(true, Ordering::SeqCst);
        assert!(ctrl.disable().is_err());
        assert!(ctrl.is_active(), "state must stay so recovery can retry");
        mock.fail_disable.store(false, Ordering::SeqCst);
        assert!(ctrl.recover().unwrap().is_some());
        assert_eq!(mock.snapshot(), before);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unsupported_backend_is_never_touched() {
        let (mock, ctrl, dir) = setup("unsupported", &[("server", "orig:1")]);
        mock.unsupported.store(true, Ordering::SeqCst);
        let before = mock.snapshot();
        assert!(matches!(
            ctrl.enable(&addr(), &[]),
            Err(ProxyError::Unsupported)
        ));
        assert_eq!(mock.snapshot(), before);
        assert!(!ctrl.is_active());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn close_restores_and_blocks_later_enables() {
        let (mock, ctrl, dir) = setup("close", &[("server", "orig:1")]);
        let before = mock.snapshot();
        ctrl.enable(&addr(), &[]).unwrap();
        ctrl.close();
        assert_eq!(mock.snapshot(), before);
        assert!(matches!(ctrl.enable(&addr(), &[]), Err(ProxyError::Closed)));
        assert_eq!(
            mock.snapshot(),
            before,
            "a late enable must not re-apply the proxy"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupt_state_file_is_an_error_not_a_panic() {
        let (_mock, ctrl, dir) = setup("corrupt", &[]);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("state.json"), "{ not json").unwrap();
        assert!(ctrl.recover().is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
