use crate::platform::{PlatformError, SystemProxy};

pub struct Proxy;

impl SystemProxy for Proxy {
    fn is_supported(&self) -> bool {
        false
    }
    fn enable(&self, _addr: &str, _bypass: &[String]) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn disable(&self) -> Result<(), PlatformError> {
        Err(PlatformError::NotImplemented)
    }
    fn current(&self) -> Result<Option<String>, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
}
