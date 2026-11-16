//! Local IPC on Windows: the named pipe `\\.\pipe\elf-gate-<SID of the user>`; the first
//! instance of the pipe is the single-instance lock. The pipe's owner is the user's SID and its
//! DACL lets in only that SID and SYSTEM.
//! The name is not secret, so somebody else may have created the pipe first: the client reads
//! the OWNER of the pipe object and refuses one that is not its own user. (The owner is set by
//! the creator in the security descriptor, so an elevated daemon of the same user passes, which
//! reading the server process's token would not allow.)

use crate::platform::{AcceptFuture, BoxStream, IpcBindError, IpcListener, PlatformError};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

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

/// `S-1-5-21-...` for a SID.
fn sid_to_string(sid: PSID) -> std::io::Result<String> {
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
    sid_to_string(sid)
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

/// The owner of the kernel object behind `handle`, as a SID string.
fn owner_sid(handle: HANDLE) -> std::io::Result<String> {
    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `handle` is a live pipe handle opened with read access; the out pointers are valid.
    // `owner` points into `descriptor`, which is freed below after the text is made.
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    let out = if rc.0 == 0 {
        sid_to_string(owner)
    } else {
        Err(std::io::Error::from_raw_os_error(rc.0 as i32))
    };
    // SAFETY: allocated by GetSecurityInfo, freed once.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    out
}

struct Listener {
    name: String,
    sid: String,
    next: NamedPipeServer,
}

fn create(name: &str, sid: &str, first: bool) -> std::io::Result<NamedPipeServer> {
    // Owner: the user. DACL (protected): the user and SYSTEM, nobody else. Integrity label:
    // medium, no write up. An elevated daemon would otherwise label the pipe "high", and the
    // user's ordinary (medium) client could not write to it.
    let sddl: Vec<u16> = format!("O:{sid}D:P(A;;GA;;;{sid})(A;;GA;;;SY)S:(ML;;NW;;;ME)\0")
        .encode_utf16()
        .collect();
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
            let fresh = create(&self.name, &self.sid, false)?;
            let connected = std::mem::replace(&mut self.next, fresh);
            Ok(Box::new(connected) as BoxStream)
        })
    }
}

pub fn bind() -> Result<Box<dyn IpcListener>, IpcBindError> {
    let sid = own_sid().map_err(|e| IpcBindError::Other(e.to_string()))?;
    let name = format!(r"\\.\pipe\elf-gate-{sid}");
    match create(&name, &sid, true) {
        Ok(next) => Ok(Box::new(Listener { name, sid, next })),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(IpcBindError::AlreadyRunning)
        }
        Err(e) => Err(IpcBindError::Other(e.to_string())),
    }
}

pub async fn connect() -> std::io::Result<BoxStream> {
    let client = ClientOptions::new().open(pipe_name()?)?;
    if owner_sid(HANDLE(client.as_raw_handle()))? != own_sid()? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the pipe belongs to another user",
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
