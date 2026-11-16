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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::ChildGuard;
    use std::time::{Duration, Instant};

    fn alive(pid: u32) -> bool {
        // A zombie is dead for our purposes.
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| {
                s.rsplit_once(')')
                    .map(|(_, r)| r.trim_start().starts_with(['R', 'S', 'D']))
            })
            .unwrap_or(false)
    }

    /// Starts `sleep` from a thread of its own, runs `then` there, and returns the pid.
    fn spawn_from_thread(then: impl FnOnce() + Send + 'static) -> u32 {
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let pid = rt.block_on(async {
                let mut cmd = tokio::process::Command::new("sleep");
                cmd.arg("30").kill_on_drop(false);
                Guard.prepare(&mut cmd);
                cmd.spawn().unwrap().id().unwrap()
            });
            then();
            pid
        })
        .join()
        .unwrap()
    }

    /// Pins the constraint described in `prepare`: the core dies with the THREAD that started
    /// it. Code that starts the core from a short-lived thread (for example `spawn_blocking`)
    /// would lose it. If this test ever fails, PDEATHSIG semantics changed: revisit `prepare`.
    #[test]
    fn child_dies_with_the_thread_that_started_it() {
        let pid = spawn_from_thread(|| ());
        let deadline = Instant::now() + Duration::from_secs(3);
        while alive(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(!alive(pid), "child {pid} outlived its spawning thread");
    }

    #[test]
    fn child_lives_while_its_thread_lives() {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let (ptx, prx) = std::sync::mpsc::channel::<u32>();
        let t = std::thread::spawn(move || {
            let pid = spawn_from_thread_inline();
            ptx.send(pid).unwrap();
            rx.recv().unwrap();
            pid
        });
        let pid = prx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(alive(pid));
        tx.send(()).unwrap();
        t.join().unwrap();
        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
    }

    fn spawn_from_thread_inline() -> u32 {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let pid = rt.block_on(async {
            let mut cmd = tokio::process::Command::new("sleep");
            cmd.arg("30");
            Guard.prepare(&mut cmd);
            cmd.spawn().unwrap().id().unwrap()
        });
        std::mem::forget(rt);
        pid
    }
}
