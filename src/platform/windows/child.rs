use crate::platform::{ChildGuard, PlatformError};
use std::sync::OnceLock;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Console::{
    AttachConsole, FreeConsole, GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};

/// Owns the job handle for the lifetime of the process. When elf-gate dies for any
/// reason, Windows closes the handle and kills every process in the job.
struct Job(HANDLE);

// SAFETY: a job object handle may be used from any thread.
unsafe impl Send for Job {}
unsafe impl Sync for Job {}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: the handle was created by CreateJobObjectW and is closed exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

static JOB: OnceLock<Result<Job, String>> = OnceLock::new();

fn job() -> Result<&'static Job, PlatformError> {
    JOB.get_or_init(|| {
        // SAFETY: plain Win32 calls; `info` outlives the call and its size is passed correctly.
        unsafe {
            let handle = CreateJobObjectW(None, None).map_err(|e| e.to_string())?;
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .map_err(|e| e.to_string())?;
            Ok(Job(handle))
        }
    })
    .as_ref()
    .map_err(|_| PlatformError::Unsupported("failed to create Job Object"))
}

pub struct Guard;

/// Nothing to report on Windows.
pub fn restrictions() -> String {
    String::new()
}

/// One console attachment at a time: a process can be attached to a single console.
static CONSOLE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Sends CTRL_BREAK to the process group of `pid`: the core, started with
/// CREATE_NEW_PROCESS_GROUP, so the group id is its pid. Go reads it as `os.Interrupt` and the
/// core closes its inbounds (the TUN adapter among them) before it exits.
///
/// The background process has no console of its own and the core has a hidden one, so the
/// event can only arrive after attaching to the core's console. Our own process is not in the
/// target group and is not hit.
fn ctrl_break(pid: u32) -> Result<(), String> {
    let _one_at_a_time = crate::sync::lock(&CONSOLE);
    // SAFETY: plain console calls; the attachment is undone before returning.
    unsafe {
        // A process may have only one console: leave ours, if there is one.
        let _ = FreeConsole();
        AttachConsole(pid).map_err(|e| format!("AttachConsole: {e}"))?;
        let sent = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid)
            .map_err(|e| format!("GenerateConsoleCtrlEvent: {e}"));
        let _ = FreeConsole();
        sent
    }
}

impl ChildGuard for Guard {
    fn prepare(&self, cmd: &mut tokio::process::Command) {
        // A group of its own: only then CTRL_BREAK can be aimed at the core alone.
        cmd.creation_flags(CREATE_NO_WINDOW.0 | CREATE_NEW_PROCESS_GROUP.0);
    }

    fn attach(&self, child: &tokio::process::Child) -> Result<(), PlatformError> {
        let job = job()?;
        let raw = child
            .raw_handle()
            .ok_or(PlatformError::Unsupported("child already exited"))?;
        // SAFETY: `raw` is a live process handle owned by `child`; the job handle is valid.
        unsafe { AssignProcessToJobObject(job.0, HANDLE(raw as _)) }
            .map_err(|_| PlatformError::Unsupported("AssignProcessToJobObject failed"))
    }

    fn own_process_group(&self, _cmd: &mut tokio::process::Command) {}

    fn terminate(&self, child: &mut tokio::process::Child) {
        // Soft first (the caller waits and kills after a timeout): a core killed outright
        // cannot remove its TUN adapter, and the next start finds it still there.
        let soft = child.id().map(ctrl_break);
        if !matches!(soft, Some(Ok(()))) {
            if let Some(Err(e)) = soft {
                tracing::warn!("soft stop failed, killing the core: {e}");
            }
            let _ = child.start_kill();
        }
    }
}
