use crate::platform::Privileges;

pub struct Elevation;

impl Privileges for Elevation {
    fn is_elevated(&self) -> bool {
        false
    }
}
