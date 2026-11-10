use crate::platform::{PlatformError, ShutdownSignals};
use std::sync::OnceLock;
use windows::core::BOOL;
use windows::Win32::System::Console::{
    SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT,
    CTRL_SHUTDOWN_EVENT,
};

static CALLBACK: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

/// Runs on a thread created by the system. For close, logoff and shutdown Windows ends the
/// process soon after the handler returns, so the callback does its work synchronously.
unsafe extern "system" fn handler(ctrl_type: u32) -> BOOL {
    match ctrl_type {
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT | CTRL_BREAK_EVENT => {
            if let Some(cb) = CALLBACK.get() {
                cb();
            }
            BOOL(1)
        }
        // Ctrl+C is a key press in raw mode, not a console event.
        _ => BOOL(0),
    }
}

pub struct Signals;

impl ShutdownSignals for Signals {
    fn install(&self, on_shutdown: Box<dyn Fn() + Send + Sync>) -> Result<(), PlatformError> {
        CALLBACK
            .set(on_shutdown)
            .map_err(|_| PlatformError::Failed("shutdown handler already installed".into()))?;
        // SAFETY: `handler` has the required signature and lives for the whole process.
        unsafe { SetConsoleCtrlHandler(Some(handler), true) }
            .map_err(|e| PlatformError::Failed(format!("SetConsoleCtrlHandler: {e}")))
    }
}
