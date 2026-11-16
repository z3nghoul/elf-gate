//! No elevated logon task on Linux: the desktop entry starts `elf-gated` as the user.

use crate::platform::LogonTask;

pub fn open() -> Option<Box<dyn LogonTask>> {
    None
}
