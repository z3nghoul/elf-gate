//! Windows facts for TUN mode: elevation, Wintun, adapters and their DNS, running programs.

use crate::platform::windows::privileges::Elevation;
use crate::platform::{Privileges, RpFilter, TunHost};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use windows::Win32::Foundation::{CloseHandle, ERROR_BUFFER_OVERFLOW};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

pub struct Host;

struct Adapter {
    name: String,
    up: bool,
    loopback: bool,
    has_gateway: bool,
    dns: Vec<String>,
}

/// SAFETY contract: `sa` is null or points to a valid SOCKADDR of the family it declares.
unsafe fn sockaddr_to_ip(
    sa: *const windows::Win32::Networking::WinSock::SOCKADDR,
) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    let family = (*sa).sa_family;
    if family == AF_INET {
        let sin = &*(sa as *const SOCKADDR_IN);
        Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
            sin.sin_addr.S_un.S_addr,
        ))))
    } else if family == AF_INET6 {
        let sin6 = &*(sa as *const SOCKADDR_IN6);
        Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.u.Byte)))
    } else {
        None
    }
}

fn adapters() -> Vec<Adapter> {
    let mut size = 16 * 1024u32;
    let mut buf: Vec<u8>;
    loop {
        buf = vec![0u8; size as usize];
        // SAFETY: `buf` is at least `size` bytes; the call fills it with a linked list of
        // IP_ADAPTER_ADDRESSES and updates `size` when more room is needed.
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_INCLUDE_GATEWAYS,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            )
        };
        if rc == ERROR_BUFFER_OVERFLOW.0 {
            continue;
        }
        if rc != 0 {
            return Vec::new();
        }
        break;
    }
    let mut out = Vec::new();
    let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    // SAFETY: the list lives inside `buf`, which outlives this loop; every pointer followed
    // is either null (end of list) or points into that buffer.
    unsafe {
        while !p.is_null() {
            let a = &*p;
            let mut dns = Vec::new();
            let mut d = a.FirstDnsServerAddress;
            while !d.is_null() {
                if let Some(ip) = sockaddr_to_ip((*d).Address.lpSockaddr) {
                    dns.push(ip.to_string());
                }
                d = (*d).Next;
            }
            out.push(Adapter {
                name: a.FriendlyName.to_string().unwrap_or_default(),
                up: a.OperStatus == IfOperStatusUp,
                loopback: a.IfType == 24,
                has_gateway: !a.FirstGatewayAddress.is_null(),
                dns,
            });
            p = a.Next;
        }
    }
    out
}

impl TunHost for Host {
    fn tun_device_present(&self) -> bool {
        true
    }

    fn wintun_missing(&self, core_dir: &Path) -> bool {
        !core_dir.join("wintun.dll").is_file()
    }

    fn trusted_binary(&self, _path: &Path) -> Result<(), String> {
        Ok(())
    }

    fn core_can_create_tun(&self, _core: &Path) -> Option<bool> {
        Some(Elevation.is_elevated())
    }

    fn core_capabilities(&self, _core: &Path) -> Option<String> {
        None
    }

    fn physical_interface(&self, _exclude: &str) -> Option<String> {
        None
    }

    fn rp_filter(&self) -> Option<RpFilter> {
        None
    }

    fn prefer_tun_adapter_dns(&self, adapter: &str, dns: &str) -> Result<(), String> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let netsh = |args: &[String]| -> Result<(), String> {
            let out = std::process::Command::new("netsh")
                .args(args)
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .map_err(|e| e.to_string())?;
            if out.status.success() {
                Ok(())
            } else {
                Err(String::from_utf8_lossy(&out.stdout).trim().to_string())
            }
        };
        netsh(&[
            "interface".into(),
            "ipv4".into(),
            "set".into(),
            "dnsservers".into(),
            format!("name={adapter}"),
            "source=static".into(),
            format!("address={dns}"),
            "validate=no".into(),
        ])?;
        netsh(&[
            "interface".into(),
            "ipv4".into(),
            "set".into(),
            "interface".into(),
            format!("name={adapter}"),
            "metric=1".into(),
        ])
    }

    fn system_dns(&self) -> Vec<String> {
        // Adapters that are up and have a gateway are the physical ones (a VPN adapter we
        // create ourselves has neither at the time of the query).
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for a in adapters()
            .into_iter()
            .filter(|a| a.up && !a.loopback && a.has_gateway)
        {
            for d in a.dns {
                let Ok(ip) = d.parse::<IpAddr>() else {
                    continue;
                };
                let usable = match ip {
                    IpAddr::V4(x) => !x.is_loopback() && !x.is_link_local(),
                    IpAddr::V6(x) => !x.is_loopback() && (x.segments()[0] & 0xffc0) != 0xfe80,
                };
                // fec0:0:0:ffff::1 and friends are Windows' placeholder resolvers.
                let placeholder = matches!(ip, IpAddr::V6(x) if x.segments()[0] == 0xfec0);
                if usable && !placeholder {
                    let list = if ip.is_ipv4() { &mut v4 } else { &mut v6 };
                    if !list.contains(&d) {
                        list.push(d);
                    }
                }
            }
        }
        v4.extend(v6);
        v4.truncate(2);
        v4
    }

    fn ipv6_enabled(&self) -> bool {
        true
    }

    fn interface_exists(&self, name: &str) -> bool {
        adapters().iter().any(|a| a.name == name)
    }

    fn running_processes(&self) -> Vec<String> {
        let mut names = Vec::new();
        // SAFETY: the snapshot handle is closed before returning, and PROCESSENTRY32W is
        // initialised with its size as the API requires.
        unsafe {
            let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
                return names;
            };
            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let len = entry
                        .szExeFile
                        .iter()
                        .position(|c| *c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                    // The core strips ".exe" when it matches process names.
                    let base = match name.len().checked_sub(4) {
                        Some(i)
                            if name.is_char_boundary(i)
                                && name[i..].eq_ignore_ascii_case(".exe") =>
                        {
                            name[..i].to_string()
                        }
                        _ => name,
                    };
                    names.push(base);
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }
        names.sort();
        names.dedup();
        names
    }

    fn kill_stale(&self, _pid: u32, _names: &[&str]) -> bool {
        // A Job Object ends the core together with elf-gate, so nothing is left behind.
        false
    }

    fn needs_supervisor(&self) -> bool {
        false
    }
}
