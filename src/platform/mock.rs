//! Test doubles for the platform traits.

use super::{PlatformError, SystemProxy};
use std::sync::Mutex;

#[derive(Default)]
pub struct MockProxy {
    pub current: Mutex<Option<String>>,
}

impl SystemProxy for MockProxy {
    fn is_supported(&self) -> bool {
        true
    }
    fn enable(&self, addr: &str, _bypass: &[String]) -> Result<(), PlatformError> {
        *self.current.lock().unwrap() = Some(addr.to_string());
        Ok(())
    }
    fn disable(&self) -> Result<(), PlatformError> {
        *self.current.lock().unwrap() = None;
        Ok(())
    }
    fn current(&self) -> Result<Option<String>, PlatformError> {
        Ok(self.current.lock().unwrap().clone())
    }
}

#[test]
fn mock_proxy_roundtrip() {
    let p = MockProxy::default();
    p.enable("127.0.0.1:10809", &[]).unwrap();
    assert_eq!(p.current().unwrap().as_deref(), Some("127.0.0.1:10809"));
    p.disable().unwrap();
    assert_eq!(p.current().unwrap(), None);
}
