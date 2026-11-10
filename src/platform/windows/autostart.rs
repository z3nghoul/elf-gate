//! Start at logon: a value in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

use super::proxy::Key;
use crate::platform::{quote_command, Autostart, PlatformError};
use windows::Win32::System::Registry::{KEY_QUERY_VALUE, KEY_SET_VALUE};

const SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE: &str = "elf-gate";

pub struct Entry;

impl Entry {
    pub fn detect() -> Self {
        Entry
    }
}

impl Autostart for Entry {
    fn is_enabled(&self) -> bool {
        Key::open_sub(SUBKEY, KEY_QUERY_VALUE)
            .and_then(|k| k.get(VALUE))
            .is_ok_and(|v| v.is_some())
    }

    fn enable(&self, command: &[String]) -> Result<(), PlatformError> {
        let key = Key::open_sub(SUBKEY, KEY_SET_VALUE)?;
        key.set_string(VALUE, &quote_command(command))
    }

    fn disable(&self) -> Result<(), PlatformError> {
        Key::open_sub(SUBKEY, KEY_SET_VALUE)?.delete(VALUE)
    }
}
