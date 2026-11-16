//! No firewall rules are managed on Linux.

use crate::platform::Firewall;

pub fn open() -> Option<Box<dyn Firewall>> {
    None
}
