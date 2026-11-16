//! TUN mode: can it run here, what to tell the user if not, the routing plan, and cleanup of
//! what a crashed run left behind. All OS facts come through `platform::TunHost`.

use crate::model::rule::{builtin_presets, effective_rules, TrafficMode};
use crate::platform::{RpFilter, TunHost};
use crate::storage::{Config, StateStore, TunState};
use crate::xray::config::{Plan, TunPlan};
use crate::xray::process::resolve_binary;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Where the privileged copy of the core lives on Linux.
pub const LINUX_CORE_DIR: &str = "/usr/local/lib/elf-gate";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// No core binary at the configured TUN path.
    CoreMissing(PathBuf),
    NoTunDevice,
    MissingWintun(PathBuf),
    /// The core would run with extra privileges but could be modified by someone else.
    UntrustedCore {
        path: PathBuf,
        reason: String,
    },
    /// The core cannot create the TUN device (no capability, not root, not administrator).
    NeedsPrivileges,
    /// `geoip.dat` / `geosite.dat` are not next to the core (the privileged copy needs its own).
    GeodataMissing(PathBuf),
    /// Not blocking: strict reverse-path filtering breaks "direct" traffic through the tunnel.
    RpFilterStrict(RpFilter),
}

impl Problem {
    pub fn is_blocking(&self) -> bool {
        !matches!(self, Problem::RpFilterStrict(_))
    }
}

/// What a successful preflight hands to the launcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setup {
    pub core: PathBuf,
    /// Run the core under the capability supervisor (Linux, not root).
    pub supervised: bool,
    pub interface: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preflight {
    pub setup: Option<Setup>,
    pub problems: Vec<Problem>,
}

impl Preflight {
    pub fn blocking(&self) -> Vec<&Problem> {
        self.problems.iter().filter(|p| p.is_blocking()).collect()
    }
}

/// The Xray used in TUN mode: `[tun].xray_path`, or on Windows (empty) the normal core.
pub fn tun_core_setting(config: &Config) -> &str {
    if config.tun.xray_path.trim().is_empty() {
        &config.core.xray_path
    } else {
        &config.tun.xray_path
    }
}

pub fn preflight(host: &dyn TunHost, config: &Config) -> Preflight {
    let mut problems = Vec::new();
    let setting = tun_core_setting(config);
    let core = match resolve_binary(setting) {
        Ok(p) => Some(p),
        Err(_) => {
            problems.push(Problem::CoreMissing(PathBuf::from(setting)));
            None
        }
    };
    if !host.tun_device_present() {
        problems.push(Problem::NoTunDevice);
    }
    if let Some(core) = &core {
        if let Some(dir) = core.parent() {
            if host.wintun_missing(dir) {
                problems.push(Problem::MissingWintun(dir.join("wintun.dll")));
            }
        }
        let assets = crate::xray::process::asset_dir(core);
        if !assets.join("geoip.dat").is_file() || !assets.join("geosite.dat").is_file() {
            problems.push(Problem::GeodataMissing(assets));
        }
        if let Err(reason) = host.trusted_binary(core) {
            problems.push(Problem::UntrustedCore {
                path: core.clone(),
                reason,
            });
        } else if host.core_can_create_tun(core) == Some(false) {
            problems.push(Problem::NeedsPrivileges);
        }
    }
    if let Some(rp) = host.rp_filter().filter(|rp| rp.value == 1) {
        problems.push(Problem::RpFilterStrict(rp));
    }
    let setup = core
        .filter(|_| problems.iter().all(|p| !p.is_blocking()))
        .map(|core| Setup {
            core,
            supervised: host.needs_supervisor(),
            interface: config.tun.name.clone(),
        });
    Preflight { setup, problems }
}

/// Shell commands that install a root-owned, capability-carrying copy of the core.
/// elf-gate never runs them: `sudo` is the user's decision.
pub fn install_commands(current_core: Option<&Path>, dest_dir: &str) -> Vec<String> {
    let src = current_core
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| crate::t!("tun.path_to_xray"));
    let src_dir = current_core
        .and_then(|p| p.parent())
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| crate::t!("tun.path_to"));
    vec![
        format!("sudo install -d -m 0755 -o root -g root {dest_dir}"),
        format!("sudo install -m 0755 -o root -g root '{src}' {dest_dir}/xray"),
        format!("sudo install -m 0644 -o root -g root '{src_dir}/geoip.dat' '{src_dir}/geosite.dat' {dest_dir}/"),
        format!("sudo setcap {PROCESS_CAPS} {dest_dir}/xray"),
    ]
}

/// A message for the UI (and logs) for one problem. Russian, with the exact commands where
/// the user has to do something by hand.
pub fn explain(problem: &Problem, config: &Config) -> String {
    let normal_core = resolve_binary(&config.core.xray_path).ok();
    let cmds = || install_commands(normal_core.as_deref(), LINUX_CORE_DIR).join("\n  ");
    match problem {
        Problem::CoreMissing(p) if crate::platform::IS_WINDOWS => {
            crate::t!("tun.core_missing_win", path = p.display())
        }
        Problem::CoreMissing(p) => crate::t!("tun.core_missing", path = p.display(), cmds = cmds()),
        Problem::GeodataMissing(dir) => {
            crate::t!("tun.geodata_missing", dir = dir.display(), cmds = cmds())
        }
        Problem::NoTunDevice => crate::t!("tun.no_device"),
        Problem::MissingWintun(p) => crate::t!("tun.wintun_missing", path = p.display()),
        Problem::UntrustedCore { path, reason } => crate::t!(
            "tun.untrusted",
            path = path.display(),
            reason = reason,
            cmds = cmds()
        ),
        Problem::NeedsPrivileges if crate::platform::IS_WINDOWS => crate::t!("tun.needs_admin"),
        Problem::NeedsPrivileges => {
            crate::t!("tun.needs_caps", caps = PROCESS_CAPS, dir = LINUX_CORE_DIR)
        }
        Problem::RpFilterStrict(rp) => crate::t!("tun.rp_filter", iface = rp.interface),
    }
}

/// Capabilities the core needs to see the owner of connections of OTHER users' programs and of
/// sandboxed (non-dumpable) ones: Chromium/Electron, Discord in Flatpak, system services.
pub const PROCESS_CAPS: &str = "cap_net_admin,cap_sys_ptrace,cap_dac_read_search+ep";

/// `Some(text)` when process rules exist but the core's capabilities (as `getcap` prints them)
/// lack what process detection needs. Not an error: the rules still work for the user's own,
/// ordinary programs.
pub fn process_caps_warning(caps: Option<&str>, has_process_rules: bool) -> Option<String> {
    let caps = caps?;
    if !has_process_rules
        || (caps.contains("cap_sys_ptrace") && caps.contains("cap_dac_read_search"))
    {
        return None;
    }
    Some(crate::t!(
        "tun.caps_warning",
        have = caps.split_whitespace().last().unwrap_or(caps),
        caps = PROCESS_CAPS,
        dir = LINUX_CORE_DIR
    ))
}

/// An Xray start error that really means "no rights".
pub fn looks_like_missing_privileges(error_text: &str) -> bool {
    let t = error_text.to_lowercase();
    t.contains("operation not permitted")
        || t.contains("access is denied")
        || t.contains("required privilege")
        || LOCALIZED_PRIVILEGE_ERRORS.iter().any(|m| t.contains(m))
        || crate::xray::validate::windows_error_codes(error_text)
            .iter()
            .any(|c| {
                [
                    crate::xray::validate::ERROR_ACCESS_DENIED,
                    crate::xray::validate::ERROR_PRIVILEGE_NOT_HELD,
                ]
                .contains(c)
            })
}

/// The adapter of the previous core is still there: Wintun answers "file already exists"
/// (0xC0000035 / 0xB7), in the system language on Windows (lower case, as matched).
pub fn looks_like_adapter_exists(error_text: &str) -> bool {
    let t = error_text.to_lowercase();
    t.contains("0xc0000035")
        || t.contains("0x000000b7")
        || t.contains("cannot create a file when that file already exists")
        || (t.contains(ADAPTER_EXISTS_RU[0]) && t.contains(ADAPTER_EXISTS_RU[1]))
        || (t.contains(ADAPTER_EXISTS_UK[0])
            && (t.contains(ADAPTER_EXISTS_UK[1]) || t.contains(ADAPTER_EXISTS_UK[2])))
}

/// "create a file" and "already exists" in Russian and Ukrainian system messages.
const ADAPTER_EXISTS_RU: [&str; 2] = [
    "\u{441}\u{43e}\u{437}\u{434}\u{430}\u{442}\u{44c} \u{444}\u{430}\u{439}\u{43b}",
    "\u{443}\u{436}\u{435} \u{441}\u{443}\u{449}\u{435}\u{441}\u{442}\u{432}\u{443}\u{435}\u{442}",
];
const ADAPTER_EXISTS_UK: [&str; 3] = [
    "\u{441}\u{442}\u{432}\u{43e}\u{440}\u{438}\u{442}\u{438} \u{444}\u{430}\u{439}\u{43b}",
    "\u{432}\u{436}\u{435} \u{456}\u{441}\u{43d}\u{443}\u{454}",
    "\u{443}\u{436}\u{435} \u{456}\u{441}\u{43d}\u{443}\u{454}",
];

/// Windows Go prints system errors in the system language (lower case, as matched).
/// Samples to be confirmed on a Russian and a Ukrainian Windows (docs/windows-checklist.md).
const LOCALIZED_PRIVILEGE_ERRORS: [&str; 5] = [
    "\u{43e}\u{442}\u{43a}\u{430}\u{437}\u{430}\u{43d}\u{43e} \u{432} \u{434}\u{43e}\u{441}\u{442}\u{443}\u{43f}\u{435}",
    "\u{43d}\u{435} \u{43e}\u{431}\u{43b}\u{430}\u{434}\u{430}\u{435}\u{442} \u{442}\u{440}\u{435}\u{431}\u{443}\u{435}\u{43c}\u{44b}\u{43c}",
    "\u{432}\u{456}\u{434}\u{43c}\u{43e}\u{432}\u{43b}\u{435}\u{43d}\u{43e} \u{432} \u{434}\u{43e}\u{441}\u{442}\u{443}\u{43f}\u{456}",
    "\u{434}\u{43e}\u{441}\u{442}\u{443}\u{43f} \u{437}\u{430}\u{431}\u{43e}\u{440}\u{43e}\u{43d}\u{435}\u{43d}\u{43e}",
    "\u{43d}\u{435} \u{43c}\u{430}\u{454} \u{43d}\u{435}\u{43e}\u{431}\u{445}\u{456}\u{434}\u{43d}\u{438}\u{445}",
];

// ------------------------------------------------------------------- the plan

/// Routing plan for a connection: rules and presets merged for the chosen routing mode,
/// plus TUN details when `traffic` is TUN.
pub fn build_plan(
    config: &Config,
    host: &dyn TunHost,
    traffic: TrafficMode,
    vps_ip: Option<IpAddr>,
) -> Plan {
    let routing = config.mode.routing;
    let rules = effective_rules(
        routing,
        &config.rules,
        &config.presets.enabled,
        &builtin_presets(),
        crate::platform::IS_WINDOWS,
    );
    let tun = (traffic == TrafficMode::Tun).then(|| TunPlan {
        name: config.tun.name.clone(),
        ipv6: host.ipv6_enabled(),
        windows: crate::platform::IS_WINDOWS,
        tunnel_dns: config.tun.tunnel_dns.clone(),
        local_dns: if config.tun.local_dns.is_empty() {
            host.system_dns()
        } else {
            config.tun.local_dns.clone()
        },
    });
    Plan {
        traffic,
        routing,
        rules,
        tun,
        vps_ip: vps_ip.map(|ip| ip.to_string()),
        failover: None,
        direct_ips: Vec::new(),
        direct_domains: Vec::new(),
        pin: std::collections::HashMap::new(),
    }
}

/// Resolves the server address before the tunnel exists, so Xray never has to resolve it
/// through the tunnel (it cannot, see docs/tun-research.md). IPv4 is preferred.
pub async fn resolve_server(address: &str, port: u16) -> Result<IpAddr, String> {
    if let Ok(ip) = address.parse::<IpAddr>() {
        return Ok(ip);
    }
    let addrs = timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((address, port)),
    )
    .await
    .map_err(|_| crate::t!("tun.dns_timeout", address = address))?
    .map_err(|e| crate::t!("tun.dns_error", address = address, error = e))?
    .collect::<Vec<_>>();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .map(|a| a.ip())
        .ok_or_else(|| crate::t!("tun.no_addresses", address = address))
}

/// Resolves every name (in parallel, a few seconds at most) and returns all addresses; names that
/// do not resolve are skipped. Used before the tunnel exists, for the "never through the tunnel" list.
pub async fn resolve_all(hosts: &[String]) -> Vec<IpAddr> {
    let mut set = tokio::task::JoinSet::new();
    for h in hosts {
        let h = h.clone();
        set.spawn(async move {
            if let Ok(ip) = h.parse::<IpAddr>() {
                return vec![ip];
            }
            match timeout(
                Duration::from_secs(3),
                tokio::net::lookup_host((h.as_str(), 443)),
            )
            .await
            {
                Ok(Ok(addrs)) => addrs.map(|a| a.ip()).collect(),
                _ => Vec::new(),
            }
        });
    }
    let mut out: Vec<IpAddr> = Vec::new();
    while let Some(Ok(ips)) = set.join_next().await {
        for ip in ips {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

/// Host name -> address for every name that is not already an address (a complete provider
/// config has several hops; Xray cannot resolve them through the tunnel once it is up).
pub async fn resolve_map(hosts: &[String]) -> std::collections::HashMap<String, String> {
    let mut set = tokio::task::JoinSet::new();
    for h in hosts.iter().filter(|h| h.parse::<IpAddr>().is_err()) {
        let h = h.clone();
        set.spawn(async move { (h.clone(), resolve_server(&h, 443).await.ok()) });
    }
    let mut out = std::collections::HashMap::new();
    while let Some(Ok((h, ip))) = set.join_next().await {
        if let Some(ip) = ip {
            out.insert(h, ip.to_string());
        }
    }
    out
}

/// WSAEACCES (10013) and EACCES: this machine refused the connection (a firewall, an antivirus,
/// another VPN's network filter); the server itself was never asked, so it says nothing about it.
pub fn is_local_block(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(10013)
}

/// Why the server could not be reached over TCP.
#[derive(Debug, PartialEq, Eq)]
pub struct Unreachable {
    pub text: String,
    /// This machine refused the connection (see [`is_local_block`]): the server was never asked.
    pub local_block: bool,
}

impl Unreachable {
    fn plain(text: String) -> Self {
        Self {
            text,
            local_block: false,
        }
    }
}

/// The words for a refused connect: a local block (never the server's fault) or a plain failure.
fn connect_failure(ip: IpAddr, port: u16, e: &std::io::Error) -> String {
    if is_local_block(e) {
        crate::t!("tun.blocked_locally", addr = SocketAddr::new(ip, port))
    } else {
        crate::t!("tun.unreachable", ip = ip, port = port, error = e)
    }
}

/// Is the server reachable over TCP at all? Must run before the tunnel is up: afterwards
/// this machine's own connections would go through the tunnel.
pub async fn tcp_reachable(ip: IpAddr, port: u16, limit: Duration) -> Result<(), Unreachable> {
    match timeout(limit, TcpStream::connect((ip, port))).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(Unreachable {
            text: connect_failure(ip, port, &e),
            local_block: is_local_block(&e),
        }),
        Err(_) => Err(Unreachable::plain(crate::t!(
            "tun.unreachable_timeout",
            ip = ip,
            port = port,
            secs = limit.as_secs()
        ))),
    }
}

/// How long a start waits for the previous adapter of the same name to go away.
pub const ADAPTER_WAIT: Duration = Duration::from_secs(5);
pub const ADAPTER_POLL: Duration = Duration::from_millis(250);

/// Before a TUN start: waits (up to `wait`) until no adapter called `name` exists, then removes
/// whatever of ours is still there, present or a ghost. Returns how many devices were removed.
/// Does nothing where the adapter goes away with the core (`adapter_lifecycle_managed`).
pub async fn free_adapter(
    host: &dyn TunHost,
    name: &str,
    wait: Duration,
    poll: Duration,
) -> Result<usize, String> {
    if !host.adapter_lifecycle_managed() {
        return Ok(0);
    }
    let deadline = tokio::time::Instant::now() + wait;
    while host.interface_exists(name) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(poll).await;
    }
    host.remove_stale_adapter(name)
}

// ------------------------------------------------------------------- state / cleanup

pub fn mark_up(store: &StateStore, pid: u32, interface: &str) {
    if let Ok(mut state) = store.load() {
        state.tun = Some(TunState {
            pid,
            interface: interface.to_string(),
        });
        let _ = store.save(&state);
    }
}

pub fn mark_down(store: &StateStore) {
    if let Ok(mut state) = store.load() {
        if state.tun.take().is_some() {
            let _ = store.save(&state);
        }
    }
}

/// At startup: stop a core a crashed run left behind and report what happened.
pub fn cleanup_stale(host: &dyn TunHost, store: &StateStore) -> Option<String> {
    let state = store.load().ok()?;
    let tun = state.tun?;
    let killed = host.kill_stale(
        tun.pid,
        &[
            "xray",
            "xray.exe",
            "elf-gate",
            "elf-gate.exe",
            "elf-gated",
            "elf-gated.exe",
        ],
    );
    mark_down(store);
    let left = host.interface_exists(&tun.interface);
    Some(match (killed, left) {
        (true, false) => crate::t!("tun.stale_killed", iface = tun.interface),
        (true, true) => crate::t!("tun.stale_killed_left", iface = tun.interface),
        (false, true) => crate::t!("tun.stale_left", iface = tun.interface),
        (false, false) => crate::t!("tun.stale_none"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::mock::MockTunHost;
    use crate::storage::{Config, StateStore};
    use crate::test_support::TempDir;

    /// A config whose TUN core points at a real (empty) file.
    fn config_with_core(dir: &Path) -> Config {
        let core = dir.join("xray");
        std::fs::write(&core, b"x").unwrap();
        std::fs::write(dir.join("geoip.dat"), b"x").unwrap();
        std::fs::write(dir.join("geosite.dat"), b"x").unwrap();
        let mut c = Config::default();
        c.tun.xray_path = core.display().to_string();
        c
    }

    #[test]
    fn missing_geodata_next_to_the_core_blocks_with_install_commands() {
        let dir = TempDir::new("geodata");
        let cfg = config_with_core(&dir);
        std::fs::remove_file(dir.join("geoip.dat")).unwrap();
        let p = preflight(&MockTunHost::healthy(), &cfg);
        assert!(p.setup.is_none());
        let problem = p
            .problems
            .iter()
            .find(|p| matches!(p, Problem::GeodataMissing(_)))
            .expect("a geodata problem");
        assert!(problem.is_blocking());
        let text = explain(problem, &cfg);
        assert!(
            text.contains("geoip.dat") && text.contains("sudo install"),
            "{text}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_capability_warning_appears_only_when_process_rules_need_more() {
        let only_admin = Some("/usr/local/lib/elf-gate/xray cap_net_admin=ep");
        let full = Some(
            "/usr/local/lib/elf-gate/xray cap_net_admin,cap_dac_read_search,cap_sys_ptrace=ep",
        );
        let w = process_caps_warning(only_admin, true).expect("warning");
        assert!(
            w.contains("setcap cap_net_admin,cap_sys_ptrace,cap_dac_read_search+ep")
                && w.contains("no process found"),
            "{w}"
        );
        assert!(
            process_caps_warning(only_admin, false).is_none(),
            "no process rules, no warning"
        );
        assert!(process_caps_warning(full, true).is_none());
        assert!(
            process_caps_warning(None, true).is_none(),
            "unknown: stay quiet"
        );
    }

    #[test]
    fn healthy_host_gives_a_setup() {
        let dir = TempDir::new("ok");
        let cfg = config_with_core(&dir);
        let pf = preflight(&MockTunHost::healthy(), &cfg);
        assert!(pf.problems.is_empty(), "{:?}", pf.problems);
        let setup = pf.setup.unwrap();
        assert_eq!(setup.interface, "elfgate0");
        assert!(!setup.supervised);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn each_blocking_problem_is_reported_and_blocks_the_setup() {
        let dir = TempDir::new("problems");
        let cfg = config_with_core(&dir);
        type Check = fn(&Problem) -> bool;
        let cases: Vec<(MockTunHost, Check)> = vec![
            (
                MockTunHost {
                    tun_device: false,
                    ..MockTunHost::healthy()
                },
                |p| *p == Problem::NoTunDevice,
            ),
            (
                MockTunHost {
                    wintun_missing: true,
                    ..MockTunHost::healthy()
                },
                |p| matches!(p, Problem::MissingWintun(_)),
            ),
            (
                MockTunHost {
                    untrusted: Some("принадлежит не root".into()),
                    ..MockTunHost::healthy()
                },
                |p| matches!(p, Problem::UntrustedCore { .. }),
            ),
            (
                MockTunHost {
                    can_create_tun: Some(false),
                    ..MockTunHost::healthy()
                },
                |p| *p == Problem::NeedsPrivileges,
            ),
        ];
        for (host, expected) in cases {
            let pf = preflight(&host, &cfg);
            assert!(pf.problems.iter().any(expected), "{:?}", pf.problems);
            assert!(pf.setup.is_none());
        }
        // Unknown capability (getcap missing) is not a problem: the start itself decides.
        let pf = preflight(
            &MockTunHost {
                can_create_tun: None,
                ..MockTunHost::healthy()
            },
            &cfg,
        );
        assert!(pf.setup.is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_core_is_reported_with_install_commands() {
        let mut cfg = Config::default();
        cfg.tun.xray_path = "/definitely/not/here/xray".into();
        let pf = preflight(&MockTunHost::healthy(), &cfg);
        assert!(matches!(pf.problems[0], Problem::CoreMissing(_)));
        let text = explain(&pf.problems[0], &cfg);
        if crate::platform::IS_WINDOWS {
            // Windows has no root-owned copy: the core just has to sit next to elf-gate.exe.
            assert!(
                text.contains("xray.exe") && text.contains("рядом с elf-gate.exe"),
                "{text}"
            );
        } else {
            assert!(
                text.contains("sudo install")
                    && text.contains("setcap cap_net_admin,cap_sys_ptrace,cap_dac_read_search+ep"),
                "{text}"
            );
            assert!(
                text.contains("sudo elf-gate"),
                "the fallback path is mentioned: {text}"
            );
            assert!(text.contains("/usr/local/lib/elf-gate/xray"), "{text}");
        }
    }

    #[test]
    fn strict_rp_filter_warns_but_does_not_block() {
        let dir = TempDir::new("rp");
        let cfg = config_with_core(&dir);
        let host = MockTunHost {
            rp: Some(RpFilter {
                interface: "wlan0".into(),
                value: 1,
            }),
            ..MockTunHost::healthy()
        };
        let pf = preflight(&host, &cfg);
        assert_eq!(pf.problems.len(), 1);
        assert!(!pf.problems[0].is_blocking());
        assert!(pf.setup.is_some(), "a warning must not stop the start");
        let text = explain(&pf.problems[0], &cfg);
        assert!(
            text.contains("sysctl -w net.ipv4.conf.all.rp_filter=2")
                && text.contains("net.ipv4.conf.wlan0.rp_filter=2"),
            "{text}"
        );
        assert!(
            text.contains("не меняет"),
            "it must say elf-gate does not change it: {text}"
        );
        // Loose (2) and off (0) are fine.
        for v in [0u8, 2] {
            let host = MockTunHost {
                rp: Some(RpFilter {
                    interface: "wlan0".into(),
                    value: v,
                }),
                ..MockTunHost::healthy()
            };
            assert!(preflight(&host, &cfg).problems.is_empty());
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn capability_supervisor_is_requested_when_the_host_needs_it() {
        let dir = TempDir::new("sup");
        let cfg = config_with_core(&dir);
        let host = MockTunHost {
            supervisor: true,
            ..MockTunHost::healthy()
        };
        assert!(preflight(&host, &cfg).setup.unwrap().supervised);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn empty_tun_path_falls_back_to_the_normal_core() {
        let mut cfg = Config::default();
        cfg.tun.xray_path = "  ".into();
        cfg.core.xray_path = "C:/tools/xray.exe".into();
        assert_eq!(tun_core_setting(&cfg), "C:/tools/xray.exe");
    }

    #[test]
    fn an_adapter_left_behind_is_recognised_in_english_and_russian() {
        // The log from a real failure on a Russian Windows.
        let ru = "Failed to setup adapter (problem code: 0x1F, ntstatus: 0xC0000035): \
            \u{41d}\u{435}\u{432}\u{43e}\u{437}\u{43c}\u{43e}\u{436}\u{43d}\u{43e} \u{441}\u{43e}\u{437}\u{434}\u{430}\u{442}\u{44c} \u{444}\u{430}\u{439}\u{43b}, \u{442}\u{430}\u{43a} \u{43a}\u{430}\u{43a} \u{43e}\u{43d} \u{443}\u{436}\u{435} \u{441}\u{443}\u{449}\u{435}\u{441}\u{442}\u{432}\u{443}\u{435}\u{442}. (Code 0x000000B7)";
        let ru_no_code = "\u{41d}\u{435}\u{432}\u{43e}\u{437}\u{43c}\u{43e}\u{436}\u{43d}\u{43e} \u{441}\u{43e}\u{437}\u{434}\u{430}\u{442}\u{44c} \u{444}\u{430}\u{439}\u{43b}, \u{442}\u{430}\u{43a} \u{43a}\u{430}\u{43a} \u{43e}\u{43d} \u{443}\u{436}\u{435} \u{441}\u{443}\u{449}\u{435}\u{441}\u{442}\u{432}\u{443}\u{435}\u{442}.";
        let en = "Failed to start: app/proxyman/inbound: failed to start proxy > Cannot create a file when that file already exists.";
        for text in [
            ru,
            ru_no_code,
            en,
            "problem code: 0x1F, ntstatus: 0xC0000035",
        ] {
            assert!(looks_like_adapter_exists(text), "{text}");
        }
        for text in [
            "Access is denied.",
            "listen tcp 127.0.0.1:10085: bind: Only one usage of each socket address",
            "failed to find matching adapter name (Code 0x00000490)",
        ] {
            assert!(!looks_like_adapter_exists(text), "{text}");
        }
    }

    #[test]
    fn privilege_errors_are_recognised() {
        assert!(looks_like_missing_privileges("Failed to start: app/proxyman/inbound: failed to start proxy > operation not permitted"));
        assert!(looks_like_missing_privileges("Access is denied."));
        assert!(looks_like_missing_privileges("create adapter: errno 1314"));
        assert!(looks_like_missing_privileges("wintun: error code 5"));
        assert!(!looks_like_missing_privileges("wintun: errno 2"));
        assert!(looks_like_missing_privileges(
            "CreateFile wintun: Отказано в доступе."
        ));
        assert!(looks_like_missing_privileges(
            "wintun: Клиент не обладает требуемым правом."
        ));
        assert!(looks_like_missing_privileges(
            "wintun: Відмовлено в доступі."
        ));
        assert!(!looks_like_missing_privileges("address already in use"));
    }

    #[test]
    fn plan_uses_system_dns_unless_configured_and_ipv6_follows_the_host() {
        let mut cfg = Config::default();
        cfg.mode.routing = crate::model::rule::RoutingMode::Include;
        cfg.presets.enabled = vec!["discord-only".into(), "local-direct".into()];
        let host = MockTunHost {
            dns: vec!["192.168.1.1".into()],
            ipv6: false,
            ..MockTunHost::healthy()
        };
        let plan = build_plan(
            &cfg,
            &host,
            TrafficMode::Tun,
            Some("203.0.113.9".parse().unwrap()),
        );
        let tun = plan.tun.as_ref().unwrap();
        assert_eq!(tun.local_dns, ["192.168.1.1"]);
        assert!(!tun.ipv6);
        assert_eq!(plan.vps_ip.as_deref(), Some("203.0.113.9"));
        assert!(plan
            .rules
            .domains
            .contains(&"domain:discord.com".to_string()));
        assert_eq!(plan.rules.always_direct_ips, ["geoip:private"]);

        cfg.tun.local_dns = vec!["77.88.8.8".into()];
        let plan = build_plan(&cfg, &host, TrafficMode::Tun, None);
        assert_eq!(plan.tun.unwrap().local_dns, ["77.88.8.8"]);

        let plan = build_plan(&cfg, &host, TrafficMode::Proxy, None);
        assert!(plan.tun.is_none());
    }

    #[tokio::test]
    async fn server_address_is_resolved_before_the_tunnel() {
        assert_eq!(
            resolve_server("203.0.113.5", 443).await.unwrap(),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
        assert!(resolve_server("localhost", 443)
            .await
            .unwrap()
            .is_loopback());
        assert!(resolve_server("no-such-host.invalid", 443).await.is_err());
    }

    #[tokio::test]
    async fn tcp_probe_distinguishes_open_and_closed_ports() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(tcp_reachable(ip, port, Duration::from_secs(2))
            .await
            .is_ok());
        drop(listener);
        let err = tcp_reachable(ip, port, Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(err.text.contains("недоступен"), "{}", err.text);
        assert!(!err.local_block);
    }

    #[test]
    fn error_10013_is_a_local_block_not_an_unreachable_server() {
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let blocked = std::io::Error::from_raw_os_error(10013);
        let local = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        for e in [&blocked, &local] {
            assert!(is_local_block(e));
            let text = connect_failure(ip, 443, e);
            assert!(text.contains("203.0.113.5:443"), "{text}");
            assert!(text.contains("брандмауэр"), "{text}");
            assert!(!text.contains("недоступен"), "{text}");
        }
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert!(!is_local_block(&refused));
        assert!(connect_failure(ip, 443, &refused).contains("недоступен"));
    }

    #[test]
    fn cleanup_kills_a_stale_core_and_clears_the_state() {
        let dir = TempDir::new("stale");
        let store = StateStore::new(dir.path());
        mark_up(&store, 4242, "elfgate0");
        let host = MockTunHost::healthy();
        let note = cleanup_stale(&host, &store).unwrap();
        assert!(note.contains("остановлен Xray"), "{note}");
        assert_eq!(host.killed.lock().unwrap().as_slice(), &[4242]);
        assert!(store.load().unwrap().tun.is_none());
        assert!(
            cleanup_stale(&host, &store).is_none(),
            "nothing to do the second time"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cleanup_reports_a_left_interface_without_a_process() {
        let dir = TempDir::new("stale-iface");
        let store = StateStore::new(dir.path());
        mark_up(&store, 1, "elfgate0");
        let host = MockTunHost {
            kill_result: false,
            iface_present: true,
            ..MockTunHost::healthy()
        };
        let note = cleanup_stale(&host, &store).unwrap();
        assert!(note.contains("ip link del elfgate0"), "{note}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn install_commands_are_complete_and_quote_paths() {
        let cmds = install_commands(
            Some(Path::new("/home/u/bin/xray")),
            "/usr/local/lib/elf-gate",
        );
        assert_eq!(cmds.len(), 4);
        assert!(cmds[1].contains("'/home/u/bin/xray'") && cmds[1].contains("-o root -g root"));
        assert!(cmds[2].contains("geoip.dat") && cmds[2].contains("geosite.dat"));
        assert!(
            cmds[3].starts_with("sudo setcap cap_net_admin,cap_sys_ptrace,cap_dac_read_search+ep")
        );
        assert!(cmds.iter().all(|c| c.starts_with("sudo ")));
    }
}
