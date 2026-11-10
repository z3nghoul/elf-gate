//! System proxy on Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
//! (ProxyEnable, ProxyServer, ProxyOverride) plus `InternetSetOptionW` so running programs
//! (Edge, Chrome, WinINet users) pick the change up immediately.

use crate::platform::{PlatformError, ProxyAddr, ProxySnapshot, SystemProxy};
use std::collections::BTreeMap;
use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_SZ, REG_VALUE_TYPE,
};

const BACKEND: &str = "windows-registry";
const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const PROXY_ENABLE: &str = "ProxyEnable";
const PROXY_SERVER: &str = "ProxyServer";
const PROXY_OVERRIDE: &str = "ProxyOverride";

pub struct Proxy;

impl Proxy {
    pub fn detect() -> Self {
        Proxy
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn failed(what: &str, e: impl std::fmt::Display) -> PlatformError {
    PlatformError::Failed(format!("{what}: {e}"))
}

/// An open `Internet Settings` key, closed on drop.
pub(super) struct Key(HKEY);

impl Key {
    fn open(
        access: windows::Win32::System::Registry::REG_SAM_FLAGS,
    ) -> Result<Self, PlatformError> {
        Self::open_sub(SUBKEY, access)
    }

    pub(super) fn open_sub(
        subkey: &str,
        access: windows::Win32::System::Registry::REG_SAM_FLAGS,
    ) -> Result<Self, PlatformError> {
        let sub = wide(subkey);
        let mut hkey = HKEY::default();
        // SAFETY: `sub` is a NUL-terminated UTF-16 string that outlives the call and
        // `hkey` is a valid out pointer.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(sub.as_ptr()),
                None,
                access,
                &mut hkey,
            )
        };
        status.ok().map_err(|e| failed("RegOpenKeyExW", e))?;
        Ok(Key(hkey))
    }

    /// `None` if the value does not exist. DWORDs are returned as decimal strings.
    pub(super) fn get(&self, name: &str) -> Result<Option<String>, PlatformError> {
        let name_w = wide(name);
        let mut kind = REG_VALUE_TYPE::default();
        let mut len: u32 = 0;
        // SAFETY: first call only asks for the type and the required size.
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                PCWSTR(name_w.as_ptr()),
                None,
                Some(&mut kind),
                None,
                Some(&mut len),
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        status.ok().map_err(|e| failed("RegQueryValueExW", e))?;
        let mut buf = vec![0u8; len as usize];
        // SAFETY: `buf` has exactly `len` writable bytes, `len` is updated by the call.
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                PCWSTR(name_w.as_ptr()),
                None,
                Some(&mut kind),
                Some(buf.as_mut_ptr()),
                Some(&mut len),
            )
        };
        status.ok().map_err(|e| failed("RegQueryValueExW", e))?;
        buf.truncate(len as usize);
        if kind == REG_DWORD && buf.len() >= 4 {
            return Ok(Some(
                u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]).to_string(),
            ));
        }
        let units: Vec<u16> = buf
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|u| *u != 0)
            .collect();
        Ok(Some(String::from_utf16_lossy(&units)))
    }

    fn set_dword(&self, name: &str, value: u32) -> Result<(), PlatformError> {
        let name_w = wide(name);
        // SAFETY: valid NUL-terminated name and a 4-byte payload for REG_DWORD.
        unsafe {
            RegSetValueExW(
                self.0,
                PCWSTR(name_w.as_ptr()),
                None,
                REG_DWORD,
                Some(&value.to_le_bytes()),
            )
        }
        .ok()
        .map_err(|e| failed("RegSetValueExW", e))
    }

    pub(super) fn set_string(&self, name: &str, value: &str) -> Result<(), PlatformError> {
        let name_w = wide(name);
        let bytes: Vec<u8> = wide(value).iter().flat_map(|u| u.to_le_bytes()).collect();
        // SAFETY: valid NUL-terminated name; the payload is NUL-terminated UTF-16 bytes.
        unsafe { RegSetValueExW(self.0, PCWSTR(name_w.as_ptr()), None, REG_SZ, Some(&bytes)) }
            .ok()
            .map_err(|e| failed("RegSetValueExW", e))
    }

    pub(super) fn delete(&self, name: &str) -> Result<(), PlatformError> {
        let name_w = wide(name);
        // SAFETY: valid NUL-terminated name.
        let status = unsafe { RegDeleteValueW(self.0, PCWSTR(name_w.as_ptr())) };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(());
        }
        status.ok().map_err(|e| failed("RegDeleteValueW", e))
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle came from RegOpenKeyExW and is closed exactly once.
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

/// Tells WinINet clients that the proxy settings changed.
fn notify() {
    // SAFETY: both options take no buffer.
    unsafe {
        let _ = InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0);
        let _ = InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0);
    }
}

impl SystemProxy for Proxy {
    fn is_supported(&self) -> bool {
        true
    }

    fn enable(&self, addr: &ProxyAddr, bypass: &[String]) -> Result<(), PlatformError> {
        let key = Key::open(KEY_SET_VALUE)?;
        key.set_string(PROXY_SERVER, &addr.http())?;
        key.set_string(PROXY_OVERRIDE, &bypass.join(";"))?;
        key.set_dword(PROXY_ENABLE, 1)?;
        notify();
        Ok(())
    }

    fn disable(&self, previous: &ProxySnapshot) -> Result<(), PlatformError> {
        let key = Key::open(KEY_SET_VALUE)?;
        match previous
            .values
            .get(PROXY_ENABLE)
            .and_then(|v| v.parse::<u32>().ok())
        {
            Some(v) => key.set_dword(PROXY_ENABLE, v)?,
            None => key.delete(PROXY_ENABLE)?,
        }
        for name in [PROXY_SERVER, PROXY_OVERRIDE] {
            match previous.values.get(name) {
                Some(v) => key.set_string(name, v)?,
                None => key.delete(name)?,
            }
        }
        notify();
        Ok(())
    }

    fn current(&self) -> Result<ProxySnapshot, PlatformError> {
        let key = Key::open(KEY_QUERY_VALUE)?;
        let mut values = BTreeMap::new();
        for name in [PROXY_ENABLE, PROXY_SERVER, PROXY_OVERRIDE] {
            if let Some(v) = key.get(name)? {
                values.insert(name.to_string(), v);
            }
        }
        Ok(ProxySnapshot {
            backend: BACKEND.into(),
            values,
        })
    }
}
