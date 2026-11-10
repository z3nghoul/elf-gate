//! `elf-gate --supervise <program> <args...>`: keeps a capability-carrying core tied to the
//! lifetime of elf-gate.
//!
//! The kernel clears the parent-death signal when a binary with file capabilities is executed,
//! so the core would outlive a killed elf-gate (and its TUN with it). This small process sits
//! in between: it gets SIGTERM when elf-gate dies and then stops the core itself.

use nix::sys::prctl::set_pdeathsig;
use nix::sys::signal::{kill, SigSet, Signal};
use nix::unistd::{getppid, Pid};
use std::process::Command;
use std::time::Duration;

pub fn run(argv: &[String]) -> i32 {
    let Some((program, args)) = argv.split_first() else {
        eprintln!("usage: elf-gate --supervise <program> [args...]");
        return 2;
    };
    // Block the stop signals before any thread exists, so `sigset.wait()` below receives them.
    let mut sigset = SigSet::empty();
    for s in [Signal::SIGTERM, Signal::SIGINT, Signal::SIGHUP] {
        sigset.add(s);
    }
    if sigset.thread_block().is_err() {
        eprintln!("cannot block signals");
        return 1;
    }
    // When elf-gate dies, the kernel sends SIGTERM (a catchable signal, unlike SIGKILL).
    let _ = set_pdeathsig(Signal::SIGTERM);
    if getppid() == Pid::from_raw(1) {
        return 1; // elf-gate is already gone
    }

    let mut child = match Command::new(program).args(args).spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot start {program}: {e}");
            return 127;
        }
    };
    let child_pid = Pid::from_raw(child.id() as i32);
    // The waiter ends the whole process as soon as the core exits by itself.
    std::thread::spawn(move || {
        let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(1);
        std::process::exit(code);
    });

    let _ = sigset.wait();
    let _ = kill(child_pid, Signal::SIGTERM);
    std::thread::sleep(Duration::from_secs(3));
    // The core did not exit in time (the waiter would have ended the process).
    let _ = kill(child_pid, Signal::SIGKILL);
    1
}
