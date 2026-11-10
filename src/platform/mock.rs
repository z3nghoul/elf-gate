//! Test doubles for the platform traits.

use super::{PlatformError, ProxyAddr, ProxySnapshot, SystemProxy};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// A fake desktop: `settings` plays the role of the user's real proxy settings.
#[derive(Default)]
pub struct MockProxy {
    pub settings: Mutex<ProxySnapshot>,
    pub fail_enable: AtomicBool,
    pub fail_disable: AtomicBool,
    pub unsupported: AtomicBool,
}

impl MockProxy {
    pub fn with_user_settings(pairs: &[(&str, &str)]) -> Self {
        let mock = MockProxy::default();
        let mut s = mock.settings.lock().unwrap();
        s.backend = "mock".into();
        for (k, v) in pairs {
            s.values.insert((*k).into(), (*v).into());
        }
        drop(s);
        mock
    }

    pub fn snapshot(&self) -> ProxySnapshot {
        self.settings.lock().unwrap().clone()
    }
}

impl SystemProxy for MockProxy {
    fn is_supported(&self) -> bool {
        !self.unsupported.load(Ordering::SeqCst)
    }
    fn enable(&self, addr: &ProxyAddr, bypass: &[String]) -> Result<(), PlatformError> {
        let mut s = self.settings.lock().unwrap();
        // Half-applied on failure, like a real backend that dies midway.
        s.values.insert("server".into(), addr.http());
        if self.fail_enable.load(Ordering::SeqCst) {
            return Err(PlatformError::Failed("mock enable failed".into()));
        }
        s.values.insert("enabled".into(), "1".into());
        s.values.insert("bypass".into(), bypass.join(";"));
        Ok(())
    }
    fn disable(&self, previous: &ProxySnapshot) -> Result<(), PlatformError> {
        if self.fail_disable.load(Ordering::SeqCst) {
            return Err(PlatformError::Failed("mock disable failed".into()));
        }
        *self.settings.lock().unwrap() = previous.clone();
        Ok(())
    }
    fn current(&self) -> Result<ProxySnapshot, PlatformError> {
        Ok(self.snapshot())
    }
}

/// Lets a test keep a handle on the fake desktop after the controller took ownership of a box.
pub struct SharedMock(pub Arc<MockProxy>);

impl SystemProxy for SharedMock {
    fn is_supported(&self) -> bool {
        self.0.is_supported()
    }
    fn enable(&self, addr: &ProxyAddr, bypass: &[String]) -> Result<(), PlatformError> {
        self.0.enable(addr, bypass)
    }
    fn disable(&self, previous: &ProxySnapshot) -> Result<(), PlatformError> {
        self.0.disable(previous)
    }
    fn current(&self) -> Result<ProxySnapshot, PlatformError> {
        self.0.current()
    }
}
