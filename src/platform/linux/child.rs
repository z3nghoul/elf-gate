use crate::platform::{ChildGuard, PlatformError};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

pub struct Guard;

impl ChildGuard for Guard {
    fn prepare(&self, cmd: &mut tokio::process::Command) {
        // SAFETY: the closure runs in the forked child before exec and only calls
        // `prctl`, which is async-signal-safe. It allocates nothing and takes no locks.
        // Caveat: PDEATHSIG fires when the *thread* that spawned the child exits; tokio
        // runtime workers live as long as the runtime, so this holds for tokio::spawn.
        unsafe {
            cmd.pre_exec(|| {
                nix::sys::prctl::set_pdeathsig(Signal::SIGKILL).map_err(std::io::Error::from)?;
                Ok(())
            });
        }
    }

    fn attach(&self, _child: &tokio::process::Child) -> Result<(), PlatformError> {
        Ok(())
    }

    fn terminate(&self, child: &mut tokio::process::Child) {
        if let Some(pid) = child.id() {
            let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
        }
    }
}
