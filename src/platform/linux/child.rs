use crate::platform::ChildGuard;

pub struct Guard;

impl ChildGuard for Guard {
    fn prepare(&self, _cmd: &mut tokio::process::Command) {}
}
