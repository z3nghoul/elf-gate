//! Local IPC on Windows: the named pipe `\\.\pipe\elf-gate-<SID of the user>`; the first
//! instance of the pipe is the single-instance lock. Only the owner may connect (DACL `OW`).
//! The name is not secret, so the client also checks that the process serving the pipe runs as
//! the same user: somebody else may have created the pipe first.

use crate::platform::{AcceptFuture, BoxStream, IpcBindError, IpcListener, PlatformError};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn win_err(e: windows::core::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// A handle closed on drop.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by this module and is closed exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// The user SID (`S-1-5-21-...`) of the process behind `process`, as text.
fn process_user_sid(process: HANDLE) -> std::io::Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: `token` is a valid out pointer; the handle is closed by `Owned`.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.map_err(win_err)?;
    let token = Owned(token);
    let mut len = 0u32;
    // SAFETY: the first call only reports the size needed in `len` (and fails on purpose).
    unsafe {
        let _ = GetTokenInformation(token.0, TokenUser, None, 0, &mut len);
    }
    // u64 elements: TOKEN_USER needs 8-byte alignment.
    let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` holds at least `len` bytes.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            len,
            &mut len,
        )
    }
    .map_err(win_err)?;
    // SAFETY: the call above filled `buf` with a TOKEN_USER whose SID points into `buf`.
    let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
    let mut text = PWSTR::null();
    // SAFETY: `sid` is valid (see above); `text` receives a LocalAlloc'ed string freed below.
    unsafe { ConvertSidToStringSidW(sid, &mut text) }.map_err(win_err)?;
    // SAFETY: `text` is a valid NUL-terminated string until the LocalFree.
    let out = unsafe { text.to_string() }.map_err(|e| std::io::Error::other(e.to_string()));
    // SAFETY: allocated by ConvertSidToStringSidW, freed once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
    }
    out
}

fn own_sid() -> std::io::Result<String> {
    // SAFETY: the pseudo handle of the current process needs no closing.
    process_user_sid(unsafe { GetCurrentProcess() })
}

/// The pipe is named after the user's SID, not `%USERNAME%` (an environment variable anybody
/// can set).
fn pipe_name() -> std::io::Result<String> {
    Ok(format!(r"\\.\pipe\elf-gate-{}", own_sid()?))
}

/// Does the process serving `pipe` run as the same user as this one?
fn served_by_same_user(pipe: HANDLE) -> std::io::Result<bool> {
    let mut pid = 0u32;
    // SAFETY: `pipe` is a live client pipe handle and `pid` a valid out pointer.
    unsafe { GetNamedPipeServerProcessId(pipe, &mut pid) }.map_err(win_err)?;
    // SAFETY: the handle is closed by `Owned`.
    let server = Owned(
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.map_err(win_err)?,
    );
    Ok(process_user_sid(server.0)? == own_sid()?)
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
    let name = pipe_name().map_err(|e| IpcBindError::Other(e.to_string()))?;
    match create(&name, true) {
        Ok(next) => Ok(Box::new(Listener { name, next })),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(IpcBindError::AlreadyRunning)
        }
        Err(e) => Err(IpcBindError::Other(e.to_string())),
    }
}

pub async fn connect() -> std::io::Result<BoxStream> {
    let client = ClientOptions::new().open(pipe_name()?)?;
    let ours = served_by_same_user(HANDLE(client.as_raw_handle()))?;
    if !ours {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the pipe is served by another user's process",
        ));
    }
    Ok(Box::new(client))
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
