//! Linux facts for TUN mode: device, privileges, binary trust, reverse-path filter,
//! resolvers, processes, leftovers of a crashed run.

use crate::platform::{RpFilter, TunHost};
use nix::sys::signal::{kill, Signal};
use nix::unistd::{geteuid, Pid};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

pub struct Host;

fn read_trim(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// Base name of the program behind a pid, symlinks resolved ("python3.14", "xray").
fn exe_name(pid: u32) -> Option<String> {
    let target = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let name = target.file_name()?.to_string_lossy().into_owned();
    Some(name.trim_end_matches(" (deleted)").to_string())
}

fn numeric_pids() -> Vec<u32> {
    fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse().ok())
        .collect()
}

/// Process group id from `/proc/<pid>/stat` (the 5th field after the command name).
fn pgrp(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 2..];
    after.split_whitespace().nth(2)?.parse().ok()
}

fn alive(pid: u32) -> bool {
    fs::metadata(format!("/proc/{pid}")).is_ok()
}

/// Parses `nameserver` lines, dropping loopback stubs and link-local addresses.
pub fn parse_resolv_conf(text: &str) -> Vec<String> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("nameserver") {
            continue;
        }
        let Some(addr) = parts.next() else { continue };
        let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
            continue;
        };
        let usable = match ip {
            std::net::IpAddr::V4(a) => {
                !a.is_loopback() && !a.is_unspecified() && !a.is_link_local()
            }
            std::net::IpAddr::V6(a) => {
                !a.is_loopback() && !a.is_unspecified() && (a.segments()[0] & 0xffc0) != 0xfe80
            }
        };
        if usable {
            let list = if ip.is_ipv4() { &mut v4 } else { &mut v6 };
            if !list.contains(&addr.to_string()) {
                list.push(addr.to_string());
            }
        }
    }
    v4.extend(v6);
    v4.truncate(2);
    v4
}

/// Default route interface from `/proc/net/route` (the lowest metric among 0.0.0.0/0).
pub fn default_interface(route_table: &str) -> Option<String> {
    route_table
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 8 && f[1] == "00000000" && f[7] == "00000000")
                .then(|| (f[6].parse::<u32>().unwrap_or(u32::MAX), f[0].to_string()))
        })
        .min()
        .map(|(_, iface)| iface)
}

impl TunHost for Host {
    fn tun_device_present(&self) -> bool {
        Path::new("/dev/net/tun").exists()
    }

    fn wintun_missing(&self, _core_dir: &Path) -> bool {
        false
    }

    fn trusted_binary(&self, path: &Path) -> Result<(), String> {
        let real: PathBuf =
            fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let meta = fs::metadata(&real).map_err(|e| format!("{}: {e}", real.display()))?;
        if !meta.is_file() {
            return Err(format!("{} не файл", real.display()));
        }
        let unsafe_entry = |m: &fs::Metadata, p: &Path| -> Option<String> {
            if m.uid() != 0 {
                Some(format!(
                    "{} принадлежит не root (uid {})",
                    p.display(),
                    m.uid()
                ))
            } else if m.mode() & 0o022 != 0 {
                Some(format!(
                    "{} доступен на запись группе или всем",
                    p.display()
                ))
            } else {
                None
            }
        };
        if let Some(e) = unsafe_entry(&meta, &real) {
            return Err(e);
        }
        for dir in real.ancestors().skip(1) {
            let m = fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            if let Some(e) = unsafe_entry(&m, dir) {
                return Err(e);
            }
        }
        Ok(())
    }

    fn core_can_create_tun(&self, core: &Path) -> Option<bool> {
        if geteuid().is_root() {
            return Some(true);
        }
        let out = Command::new("getcap")
            .arg(core)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).contains("cap_net_admin"))
    }

    fn rp_filter(&self) -> Option<RpFilter> {
        let iface = default_interface(&fs::read_to_string("/proc/net/route").ok()?)?;
        let read = |p: String| read_trim(&p)?.parse::<u8>().ok();
        let all = read("/proc/sys/net/ipv4/conf/all/rp_filter".into())?;
        let own = read(format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter")).unwrap_or(0);
        // The kernel uses the larger of the two values.
        Some(RpFilter {
            interface: iface,
            value: all.max(own),
        })
    }

    fn system_dns(&self) -> Vec<String> {
        // With systemd-resolved /etc/resolv.conf only points to a loopback stub; the real
        // upstream resolvers are listed here.
        for path in ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
            if let Ok(text) = fs::read_to_string(path) {
                let servers = parse_resolv_conf(&text);
                if !servers.is_empty() {
                    return servers;
                }
            }
        }
        Vec::new()
    }

    fn ipv6_enabled(&self) -> bool {
        read_trim("/proc/sys/net/ipv6/conf/all/disable_ipv6").as_deref() == Some("0")
    }

    fn interface_exists(&self, name: &str) -> bool {
        Path::new("/sys/class/net").join(name).exists()
    }

    fn running_processes(&self) -> Vec<String> {
        // Only programs of the current user are readable; that is what the user wants to pick from.
        let mut names: Vec<String> = numeric_pids().into_iter().filter_map(exe_name).collect();
        names.sort();
        names.dedup();
        names
    }

    fn kill_stale(&self, pid: u32, names: &[&str]) -> bool {
        let matches = |p: u32| exe_name(p).is_some_and(|n| names.contains(&n.as_str()));
        let mut victims: Vec<u32> = numeric_pids()
            .into_iter()
            .filter(|p| (*p == pid || pgrp(*p) == Some(pid)) && matches(*p))
            .collect();
        victims.dedup();
        if victims.is_empty() {
            return false;
        }
        for p in &victims {
            let _ = kill(Pid::from_raw(*p as i32), Signal::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while victims.iter().any(|p| alive(*p)) && Instant::now() < deadline {
            sleep(Duration::from_millis(50));
        }
        for p in victims.iter().filter(|p| alive(**p)) {
            let _ = kill(Pid::from_raw(*p as i32), Signal::SIGKILL);
        }
        true
    }

    fn needs_supervisor(&self) -> bool {
        // PR_SET_PDEATHSIG is cleared when a binary with file capabilities is executed
        // (see prctl(2)), so a capability-carrying core would survive `kill -9` of elf-gate.
        !geteuid().is_root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf_drops_loopback_stubs_and_keeps_real_upstreams() {
        let text = "# generated\nnameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver ::1\nnameserver fe80::1%wlan0\nnameserver 2001:4860:4860::8888\nnameserver 192.168.1.1\nnameserver 8.8.8.8\n";
        assert_eq!(parse_resolv_conf(text), ["192.168.1.1", "8.8.8.8"]);
        assert!(parse_resolv_conf("nameserver 127.0.0.53\n").is_empty());
        assert_eq!(
            parse_resolv_conf("nameserver 2001:db8::53\n"),
            ["2001:db8::53"]
        );
    }

    #[test]
    fn default_interface_is_the_lowest_metric_default_route() {
        let table =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
            wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
            eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
            eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(default_interface(table).as_deref(), Some("eth0"));
        assert_eq!(default_interface("Iface\tDestination\n"), None);
    }

    #[test]
    fn processes_are_listed_by_real_file_name() {
        let names = Host.running_processes();
        assert!(!names.is_empty());
        // This test binary itself is running.
        let me = exe_name(std::process::id()).unwrap();
        assert!(names.contains(&me));
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(names, sorted);
    }

    #[test]
    fn user_owned_binaries_are_not_trusted() {
        let dir = std::env::temp_dir().join(format!("elf-gate-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("xray");
        std::fs::write(&file, b"x").unwrap();
        let err = Host.trusted_binary(&file).unwrap_err();
        assert!(
            err.contains("не root") || err.contains("на запись"),
            "{err}"
        );
        // A system binary (root-owned, not group/world writable) is fine.
        assert!(Host.trusted_binary(Path::new("/usr/bin/env")).is_ok());
        assert!(Host
            .trusted_binary(Path::new("/definitely/missing"))
            .is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn kill_stale_ignores_unrelated_pids() {
        // Our own pid is not an "xray": it must not be touched.
        assert!(!Host.kill_stale(std::process::id(), &["xray"]));
        assert!(!Host.kill_stale(4_000_000, &["xray"]));
    }
}
