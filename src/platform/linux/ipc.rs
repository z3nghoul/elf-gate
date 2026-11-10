//! Local IPC on Linux: a unix socket `$XDG_RUNTIME_DIR/elf-gate.sock` (mode 0600).
//! The socket doubles as the single-instance lock.

use crate::platform::{AcceptFuture, BoxStream, IpcBindError, IpcListener, PlatformError};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::net::{UnixListener, UnixStream};

/// `ELF_GATE_SOCKET` overrides the path (tests use isolated sockets).
fn socket_path() -> PathBuf {
    if let Some(p) = std::env::var_os("ELF_GATE_SOCKET") {
        return PathBuf::from(p);
    }
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(crate::storage::state_dir);
    dir.join("elf-gate.sock")
}

struct Listener(UnixListener, PathBuf);

impl IpcListener for Listener {
    fn accept(&mut self) -> AcceptFuture<'_> {
        Box::pin(async move {
            let (s, _) = self.0.accept().await?;
            Ok(Box::new(s) as BoxStream)
        })
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.1);
    }
}

pub fn bind() -> Result<Box<dyn IpcListener>, IpcBindError> {
    let path = socket_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // A live owner answers; a stale file (crash) refuses the connection and is replaced.
    if std::os::unix::net::UnixStream::connect(&path).is_ok() {
        return Err(IpcBindError::AlreadyRunning);
    }
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).map_err(|e| IpcBindError::Other(e.to_string()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| IpcBindError::Other(e.to_string()))?;
    Ok(Box::new(Listener(listener, path)))
}

pub async fn connect() -> std::io::Result<BoxStream> {
    Ok(Box::new(UnixStream::connect(socket_path()).await?))
}

pub fn spawn_detached(program: &Path, args: &[String]) -> Result<(), PlatformError> {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Its own process group: a Ctrl+C or a closed terminal does not reach it.
        .process_group(0);
    cmd.spawn()
        .map(|_| ())
        .map_err(|e| PlatformError::Failed(format!("{}: {e}", program.display())))
}
