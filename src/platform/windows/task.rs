//! The elevated start at logon as a Task Scheduler task, through the COM API (`schtasks` is not
//! used: its output is localised). The task belongs to the user, starts at that user's logon,
//! runs with the highest rights and is not SYSTEM, so the daemon's pipe passes the owner check.

use super::firewall::ComScope;
use crate::platform::{command_line, LogonTask, PlatformError};
use windows::core::{Interface, BSTR, HRESULT};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, VARIANT_FALSE};
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};
use windows::Win32::System::TaskScheduler::{
    IExecAction, ILogonTrigger, ITaskFolder, ITaskService, TaskScheduler, TASK_ACTION_EXEC,
    TASK_CREATE_OR_UPDATE, TASK_INSTANCES_IGNORE_NEW, TASK_LOGON_INTERACTIVE_TOKEN,
    TASK_RUNLEVEL_HIGHEST, TASK_TRIGGER_LOGON,
};
use windows::Win32::System::Variant::VARIANT;

const NAME: &str = "elf-gate autostart";

pub fn open() -> Option<Box<dyn LogonTask>> {
    Some(Box::new(Scheduler))
}

struct Scheduler;

fn fail(e: windows::core::Error) -> PlatformError {
    PlatformError::Failed(format!("Task Scheduler: {e}"))
}

fn is_missing(e: &windows::core::Error) -> bool {
    [ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND]
        .iter()
        .any(|code| e.code() == HRESULT::from_win32(code.0))
}

/// The service and its root folder. The objects must be dropped before COM is released.
fn connect() -> windows::core::Result<(ITaskService, ITaskFolder)> {
    // SAFETY: plain COM activation of the system's Task Scheduler; COM is initialised by the
    // caller's `ComScope`.
    let service: ITaskService =
        unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }?;
    let none = VARIANT::default();
    // SAFETY: `service` is live; empty variants mean "the local machine, the current user".
    unsafe { service.Connect(&none, &none, &none, &none) }?;
    // SAFETY: as above; the BSTR outlives the call.
    let root = unsafe { service.GetFolder(&BSTR::from("\\")) }?;
    Ok((service, root))
}

fn read() -> windows::core::Result<Option<String>> {
    let (_service, root) = connect()?;
    // SAFETY: `root` is live; the BSTR outlives the call.
    let task = match unsafe { root.GetTask(&BSTR::from(NAME)) } {
        Ok(task) => task,
        Err(e) if is_missing(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    // SAFETY: every object below is a live COM object owned by this function. Collections are
    // 1-based.
    unsafe {
        let actions = task.Definition()?.Actions()?;
        let exec: IExecAction = actions.get_Item(1)?.cast()?;
        let (mut path, mut arguments) = (BSTR::new(), BSTR::new());
        exec.Path(&mut path)?;
        exec.Arguments(&mut arguments)?;
        Ok(Some(command_line(
            &path.to_string(),
            &arguments.to_string(),
        )))
    }
}

fn register(user: &str, command: &[String]) -> windows::core::Result<()> {
    let (service, root) = connect()?;
    let user = BSTR::from(user);
    let (program, rest) = command.split_first().ok_or(windows::core::Error::empty())?;
    let arguments = crate::platform::quote_command(rest);
    let work_dir = std::path::Path::new(program)
        .parent()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    // SAFETY: every object below is a live COM object owned by this function; the BSTRs and
    // variants outlive the calls that borrow them.
    unsafe {
        let definition = service.NewTask(0)?;

        let principal = definition.Principal()?;
        principal.SetUserId(&user)?;
        principal.SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN)?;
        principal.SetRunLevel(TASK_RUNLEVEL_HIGHEST)?;

        // A laptop on battery still starts the VPN, and nothing ends it after a time limit.
        let settings = definition.Settings()?;
        settings.SetDisallowStartIfOnBatteries(VARIANT_FALSE)?;
        settings.SetStopIfGoingOnBatteries(VARIANT_FALSE)?;
        settings.SetExecutionTimeLimit(&BSTR::from("PT0S"))?;
        settings.SetMultipleInstances(TASK_INSTANCES_IGNORE_NEW)?;

        let trigger: ILogonTrigger = definition.Triggers()?.Create(TASK_TRIGGER_LOGON)?.cast()?;
        trigger.SetUserId(&user)?;

        let exec: IExecAction = definition.Actions()?.Create(TASK_ACTION_EXEC)?.cast()?;
        exec.SetPath(&BSTR::from(program.as_str()))?;
        exec.SetArguments(&BSTR::from(arguments))?;
        exec.SetWorkingDirectory(&BSTR::from(work_dir))?;

        root.RegisterTaskDefinition(
            &BSTR::from(NAME),
            &definition,
            TASK_CREATE_OR_UPDATE.0,
            &VARIANT::from(user),
            &VARIANT::default(),
            TASK_LOGON_INTERACTIVE_TOKEN,
            &VARIANT::default(),
        )?;
    }
    Ok(())
}

fn remove() -> windows::core::Result<()> {
    let (_service, root) = connect()?;
    // SAFETY: `root` is live; the BSTR outlives the call.
    match unsafe { root.DeleteTask(&BSTR::from(NAME), 0) } {
        Err(e) if is_missing(&e) => Ok(()),
        other => other,
    }
}

impl LogonTask for Scheduler {
    fn command(&self) -> Result<Option<String>, PlatformError> {
        let _com = ComScope::enter().map_err(PlatformError::Failed)?;
        read().map_err(fail)
    }

    fn create(&self, user: &str, command: &[String]) -> Result<(), PlatformError> {
        let _com = ComScope::enter().map_err(PlatformError::Failed)?;
        register(user, command).map_err(fail)
    }

    fn delete(&self) -> Result<(), PlatformError> {
        let _com = ComScope::enter().map_err(PlatformError::Failed)?;
        remove().map_err(fail)
    }
}
