use crate::platform::{PlatformError, ShutdownSignals};

pub struct Signals;

impl ShutdownSignals for Signals {
    fn install(&self, _on_shutdown: Box<dyn Fn() + Send + Sync>) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }
}
