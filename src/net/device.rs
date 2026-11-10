//! The identity elf-gate shows to subscription panels (HWID and the `x-*` device headers).
//! Panels that limit devices count one HWID as one slot, so it must be the same on every run
//! and for every subscription.

use crate::platform;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub hwid: String,
    pub os: String,
    pub os_version: String,
    pub model: String,
}

/// First 16 hex digits of `sha256(machine id)`.
pub fn hwid_from(machine_id: &str) -> String {
    let digest = Sha256::digest(machine_id.trim().as_bytes());
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// A new HWID: from the machine id, else from the clock and the process (random, kept in the
/// config from then on, so it still is the same on every later run).
pub fn generate_hwid() -> String {
    match platform::machine_id() {
        Some(id) => hwid_from(&id),
        None => {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(1);
            hwid_from(&format!("elf-gate-{nanos}-{}", std::process::id()))
        }
    }
}

impl DeviceInfo {
    pub fn current(hwid: &str) -> Self {
        Self {
            hwid: hwid.to_string(),
            os: if cfg!(windows) { "Windows" } else { "Linux" }.into(),
            os_version: platform::os_version(),
            model: "elf-gate".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hwid_is_stable_16_hex_and_depends_on_the_machine() {
        let a = hwid_from("0123456789abcdef");
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            a,
            hwid_from("0123456789abcdef\n"),
            "trailing newline of machine-id is ignored"
        );
        assert_ne!(a, hwid_from("fedcba9876543210"));
        // Pinned: a change would move every user to a new slot.
        assert_eq!(hwid_from("abc"), "ba7816bf8f01cfea");
    }

    #[test]
    fn the_device_headers_describe_this_machine() {
        let d = DeviceInfo::current("abcd");
        assert_eq!(d.model, "elf-gate");
        assert!(d.os == "Linux" || d.os == "Windows");
        assert!(!d.os_version.is_empty());
    }
}
