//! Removes a leftover Wintun adapter by its connection name (the name the TUN config gives it).
//!
//! A core that was killed cannot delete its adapter; the device stays (present, or "ghost" when
//! it is no longer attached) and the next start fails with "file already exists". Only devices
//! of the network class whose hardware id is Wintun's AND whose connection name is exactly the
//! one asked for are removed: other adapters, including other Wintun ones, are never touched.

use windows::core::{GUID, PCWSTR};
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiCallClassInstaller, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
    SetupDiGetClassDevsW, SetupDiGetDeviceRegistryPropertyW, SetupDiOpenDevRegKey,
    SetupDiSetClassInstallParamsW, DICS_FLAG_GLOBAL, DIF_REMOVE, DIGCF_PROFILE, DIREG_DRV,
    DI_REMOVEDEVICE_GLOBAL, HDEVINFO, SPDRP_HARDWAREID, SP_CLASSINSTALL_HEADER, SP_DEVINFO_DATA,
    SP_REMOVEDEVICE_PARAMS,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
};

/// The network adapter device class.
const NET_CLASS: GUID = GUID::from_u128(0x4d36e972_e325_11ce_bfc1_08002be10318);

/// A device information set closed on drop.
struct DeviceSet(HDEVINFO);

impl Drop for DeviceSet {
    fn drop(&mut self) {
        // SAFETY: the set was returned by SetupDiGetClassDevsW and is destroyed once.
        unsafe {
            let _ = SetupDiDestroyDeviceInfoList(self.0);
        }
    }
}

/// A registry key closed on drop.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the key was opened by this module and is closed once.
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A string value of an open key (`None` when it is missing or not text).
fn string_value(key: HKEY, name: &str) -> Option<String> {
    let name = utf16(name);
    let mut len = 0u32;
    // SAFETY: the first call only asks for the size.
    unsafe { RegQueryValueExW(key, PCWSTR(name.as_ptr()), None, None, None, Some(&mut len)) }
        .ok()
        .ok()?;
    let mut buf = vec![0u16; (len as usize).div_ceil(2) + 1];
    let mut size = (buf.len() * 2) as u32;
    // SAFETY: `buf` is `size` bytes long.
    unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(name.as_ptr()),
            None,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut size),
        )
    }
    .ok()
    .ok()?;
    let chars = (size as usize / 2).min(buf.len());
    Some(
        String::from_utf16_lossy(&buf[..chars])
            .trim_end_matches('\0')
            .to_string(),
    )
}

/// Is this a Wintun device? Its hardware id contains `wintun`.
fn is_wintun(set: HDEVINFO, data: &SP_DEVINFO_DATA) -> bool {
    let mut buf = vec![0u8; 1024];
    let mut size = 0u32;
    // SAFETY: `buf` is as long as announced.
    let ok = unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            set,
            data,
            SPDRP_HARDWAREID,
            None,
            Some(&mut buf),
            Some(&mut size),
        )
    };
    if ok.is_err() {
        return false;
    }
    let units: Vec<u16> = buf[..(size as usize).min(buf.len())]
        .chunks(2)
        .filter(|c| c.len() == 2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
        .to_lowercase()
        .contains("wintun")
}

/// The connection name of the adapter ("elfgate0"): the registry keeps it under the network
/// class key of the adapter's `NetCfgInstanceId`.
fn connection_name(set: HDEVINFO, data: &SP_DEVINFO_DATA) -> Option<String> {
    // SAFETY: the key is closed by `Key`.
    let driver_key = Key(unsafe {
        SetupDiOpenDevRegKey(set, data, DICS_FLAG_GLOBAL.0, 0, DIREG_DRV, KEY_READ.0)
    }
    .ok()?);
    let id = string_value(driver_key.0, "NetCfgInstanceId")?;
    let path = utf16(&format!(
        r"SYSTEM\CurrentControlSet\Control\Network\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\{id}\Connection"
    ));
    let mut raw = HKEY::default();
    // SAFETY: `path` is NUL-terminated; the key is closed by `Key`.
    unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            None,
            KEY_READ,
            &mut raw,
        )
    }
    .ok()
    .ok()?;
    let key = Key(raw);
    string_value(key.0, "Name")
}

/// Removes every Wintun adapter named `name` (present or ghost). Returns how many were removed.
pub fn remove_named(name: &str) -> Result<usize, String> {
    // No DIGCF_PRESENT: ghost (not attached) devices are listed too.
    // SAFETY: the set is destroyed by `DeviceSet`.
    let set = DeviceSet(
        unsafe { SetupDiGetClassDevsW(Some(&NET_CLASS), PCWSTR::null(), None, DIGCF_PROFILE) }
            .map_err(|e| format!("SetupDiGetClassDevsW: {e}"))?,
    );
    let mut removed = 0;
    let mut index = 0;
    loop {
        let mut data = SP_DEVINFO_DATA {
            cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: `data.cbSize` is set as the API requires.
        if unsafe { SetupDiEnumDeviceInfo(set.0, index, &mut data) }.is_err() {
            break;
        }
        index += 1;
        if !is_wintun(set.0, &data) {
            continue;
        }
        let Some(found) = connection_name(set.0, &data) else {
            continue;
        };
        if !found.eq_ignore_ascii_case(name) {
            continue;
        }
        let params = SP_REMOVEDEVICE_PARAMS {
            ClassInstallHeader: SP_CLASSINSTALL_HEADER {
                cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
                InstallFunction: DIF_REMOVE,
            },
            Scope: DI_REMOVEDEVICE_GLOBAL,
            HwProfile: 0,
        };
        // SAFETY: `params` starts with its header and lives through both calls.
        unsafe {
            SetupDiSetClassInstallParamsW(
                set.0,
                Some(&data),
                Some(&params.ClassInstallHeader),
                std::mem::size_of::<SP_REMOVEDEVICE_PARAMS>() as u32,
            )
        }
        .map_err(|e| format!("SetupDiSetClassInstallParamsW: {e}"))?;
        // SAFETY: the removal parameters were set above for this device.
        unsafe { SetupDiCallClassInstaller(DIF_REMOVE, set.0, Some(&data)) }
            .map_err(|e| format!("SetupDiCallClassInstaller(DIF_REMOVE): {e}"))?;
        removed += 1;
    }
    Ok(removed)
}
