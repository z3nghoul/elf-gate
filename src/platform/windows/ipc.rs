//! Local IPC on Windows: the named pipe `\\.\pipe\elf-gate-<user>`; the first instance of
//! the pipe is the single-instance lock. Only the owner may connect (DACL `OW`).

use crate::platform::{AcceptFuture, BoxStream, IpcBindError, IpcListener, PlatformError};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn pipe_name() -> String {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".into());
    format!(r"\\.\pipe\elf-gate-{user}")
}

struct Listener {
    name: String,
    next: NamedPipeServer,
}

fn create(name: &str, first: bool) -> std::io::Result<NamedPipeServer> {
    let sddl: Vec<u16> = "D:P(A;;GA;;;OW)\0".encode_utf16().collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl` is NUL-terminated and outlives the call; `sd` is a valid out pointer.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
    }
    .map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };
    // SAFETY: `attrs` points to a valid descriptor that lives until after the call.
    let server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                name,
                (&mut attrs as *mut SECURITY_ATTRIBUTES).cast(),
            )
    };
    // SAFETY: the descriptor was allocated by the conversion call above and is freed once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    server
}

impl IpcListener for Listener {
    fn accept(&mut self) -> AcceptFuture<'_> {
        Box::pin(async move {
            self.next.connect().await?;
            let fresh = create(&self.name, false)?;
            let connected = std::mem::replace(&mut self.next, fresh);
            Ok(Box::new(connected) as BoxStream)
        })
    }
}

pub fn bind() -> Result<Box<dyn IpcListener>, IpcBindError> {
    let name = pipe_name();
    match create(&name, true) {
        Ok(next) => Ok(Box::new(Listener { name, next })),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(IpcBindError::AlreadyRunning)
        }
        Err(e) => Err(IpcBindError::Other(e.to_string())),
    }
}

pub async fn connect() -> std::io::Result<BoxStream> {
    Ok(Box::new(ClientOptions::new().open(pipe_name())?))
}

pub fn spawn_detached(program: &Path, args: &[String]) -> Result<(), PlatformError> {
    std::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .map(|_| ())
        .map_err(|e| PlatformError::Failed(format!("{}: {e}", program.display())))
}
