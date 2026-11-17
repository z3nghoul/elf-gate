//! Puts the commit into the build when CI did not (`ELF_GATE_COMMIT`): the short hash from git,
//! if git is there; otherwise the program says "dev".

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=ELF_GATE_COMMIT");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
    println!("cargo:rerun-if-changed=.git/packed-refs");
    if std::env::var("ELF_GATE_COMMIT").is_ok_and(|v| !v.trim().is_empty()) {
        return;
    }
    let hash = Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|h| !h.is_empty());
    if let Some(hash) = hash {
        println!("cargo:rustc-env=ELF_GATE_COMMIT={hash}");
    }
}
