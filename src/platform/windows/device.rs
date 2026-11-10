//! Machine identity for the subscription headers.

use super::proxy::Key;
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE};

pub fn machine_id() -> Option<String> {
    Key::open_in(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Cryptography",
        KEY_QUERY_VALUE,
    )
    .ok()?
    .get("MachineGuid")
    .ok()?
    .filter(|s| !s.is_empty())
}

pub fn os_version() -> String {
    let Ok(key) = Key::open_in(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        KEY_QUERY_VALUE,
    ) else {
        return "unknown".into();
    };
    let build = key.get("CurrentBuild").ok().flatten();
    let display = key.get("DisplayVersion").ok().flatten();
    match (build, display) {
        (Some(b), Some(d)) => format!("10.0.{b} ({d})"),
        (Some(b), None) => format!("10.0.{b}"),
        _ => "unknown".into(),
    }
}
