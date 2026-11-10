use crate::platform::{PlatformError, ShutdownSignals};
use tokio::signal::unix::{signal, SignalKind};

pub struct Signals;

impl ShutdownSignals for Signals {
    /// Calls `on_shutdown` once on SIGTERM or SIGHUP (terminal closed). Must be called
    /// from inside the tokio runtime. SIGINT is not handled here: in raw mode Ctrl+C
    /// arrives as a key press.
    fn install(&self, on_shutdown: Box<dyn Fn() + Send + Sync>) -> Result<(), PlatformError> {
        let mut term = signal(SignalKind::terminate())
            .map_err(|e| PlatformError::Failed(format!("SIGTERM handler: {e}")))?;
        let mut hup = signal(SignalKind::hangup())
            .map_err(|e| PlatformError::Failed(format!("SIGHUP handler: {e}")))?;
        tokio::spawn(async move {
            tokio::select! {
                _ = term.recv() => {}
                _ = hup.recv() => {}
            }
            on_shutdown();
        });
        Ok(())
    }
}
