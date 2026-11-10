//! Test doubles for the platform traits.

use super::{PlatformError, ProxyAddr, ProxySnapshot, RpFilter, SystemProxy, TunHost};
use std::path::Path;
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

/// A scripted machine for the TUN decision logic.
pub struct MockTunHost {
    pub tun_device: bool,
    pub wintun_missing: bool,
    pub untrusted: Option<String>,
    pub can_create_tun: Option<bool>,
    pub rp: Option<RpFilter>,
    pub dns: Vec<String>,
    pub ipv6: bool,
    pub iface_present: bool,
    pub processes: Vec<String>,
    pub supervisor: bool,
    pub kill_result: bool,
    pub killed: Mutex<Vec<u32>>,
}

impl MockTunHost {
    pub fn healthy() -> Self {
        Self {
            tun_device: true,
            wintun_missing: false,
            untrusted: None,
            can_create_tun: Some(true),
            rp: None,
            dns: vec!["192.168.1.1".into()],
            ipv6: true,
            iface_present: false,
            processes: vec!["Discord".into(), "firefox".into()],
            supervisor: false,
            kill_result: true,
            killed: Mutex::new(Vec::new()),
        }
    }
}

impl TunHost for MockTunHost {
    fn tun_device_present(&self) -> bool {
        self.tun_device
    }
    fn wintun_missing(&self, _core_dir: &Path) -> bool {
        self.wintun_missing
    }
    fn trusted_binary(&self, _path: &Path) -> Result<(), String> {
        self.untrusted.clone().map_or(Ok(()), Err)
    }
    fn core_can_create_tun(&self, _core: &Path) -> Option<bool> {
        self.can_create_tun
    }
    fn rp_filter(&self) -> Option<RpFilter> {
        self.rp.clone()
    }
    fn system_dns(&self) -> Vec<String> {
        self.dns.clone()
    }
    fn ipv6_enabled(&self) -> bool {
        self.ipv6
    }
    fn interface_exists(&self, _name: &str) -> bool {
        self.iface_present
    }
    fn running_processes(&self) -> Vec<String> {
        self.processes.clone()
    }
    fn kill_stale(&self, pid: u32, _names: &[&str]) -> bool {
        self.killed.lock().unwrap().push(pid);
        self.kill_result
    }
    fn needs_supervisor(&self) -> bool {
        self.supervisor
    }
}
