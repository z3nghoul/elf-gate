use crate::platform::{ChildGuard, PlatformError};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

pub struct Guard;

/// One line about the limits of this process, read from `/proc/self`.
pub fn restrictions() -> String {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let pick = |key: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .map(|v| v.trim().replace('\t', " "))
            .unwrap_or_else(|| "?".into())
    };
    let link = |p: &str| {
        std::fs::read_link(p)
            .map(|l| l.display().to_string())
            .unwrap_or_else(|_| "?".into())
    };
    let label = std::fs::read_to_string("/proc/self/attr/current")
        .map(|s| s.trim().trim_end_matches('\0').to_string())
        .unwrap_or_else(|_| "?".into());
    format!(
        "uid: {}, gid: {}, NoNewPrivs: {}, Seccomp: {}, CapEff: {}, CapBnd: {}, mnt-ns: {}, root: {}, LSM: {}",
        pick("Uid:"),
        pick("Gid:"),
        pick("NoNewPrivs:"),
        pick("Seccomp:"),
        pick("CapEff:"),
        pick("CapBnd:"),
        link("/proc/self/ns/mnt"),
        link("/proc/self/root"),
        label
    )
}

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

    fn own_process_group(&self, cmd: &mut tokio::process::Command) {
        cmd.process_group(0);
    }

    fn terminate(&self, child: &mut tokio::process::Child) {
        if let Some(pid) = child.id() {
            let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
        }
    }
}
