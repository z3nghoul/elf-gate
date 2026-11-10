use crate::platform::{ChildGuard, PlatformError};
use std::sync::OnceLock;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::CREATE_NO_WINDOW;

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

impl ChildGuard for Guard {
    fn prepare(&self, cmd: &mut tokio::process::Command) {
        cmd.creation_flags(CREATE_NO_WINDOW.0);
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
        let _ = child.start_kill();
    }
}
