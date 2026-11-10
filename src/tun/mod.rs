//! TUN mode: can it run here, what to tell the user if not, the routing plan, and cleanup of
//! what a crashed run left behind. All OS facts come through `platform::TunHost`.

use crate::model::rule::{builtin_presets, effective_rules, TrafficMode};
use crate::platform::{RpFilter, TunHost};
use crate::storage::{Config, StateStore, TunState};
use crate::xray::config::{Plan, TunPlan};
use crate::xray::process::resolve_binary;
use std::net::IpAddr;
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
        .unwrap_or_else(|| "/путь/к/xray".into());
    let src_dir = current_core
        .and_then(|p| p.parent())
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "/путь/к".into());
    vec![
        format!("sudo install -d -m 0755 -o root -g root {dest_dir}"),
        format!("sudo install -m 0755 -o root -g root '{src}' {dest_dir}/xray"),
        format!("sudo install -m 0644 -o root -g root '{src_dir}/geoip.dat' '{src_dir}/geosite.dat' {dest_dir}/"),
        format!("sudo setcap cap_net_admin+ep {dest_dir}/xray"),
    ]
}

/// A message for the UI (and logs) for one problem. Russian, with the exact commands where
/// the user has to do something by hand.
pub fn explain(problem: &Problem, config: &Config) -> String {
    let normal_core = resolve_binary(&config.core.xray_path).ok();
    match problem {
        Problem::CoreMissing(p) if cfg!(windows) => format!(
            "Не найден xray.exe для режима TUN: {}. Положите его рядом с elf-gate.exe.",
            p.display()
        ),
        Problem::CoreMissing(p) => format!(
            "Для режима TUN нужна копия Xray, принадлежащая root: {} не найден.\n\nУстановка (выполните сами, elf-gate sudo не вызывает):\n  {}\n\nЗапасной путь: запустить  sudo elf-gate  (конфиг останется в вашей домашней папке).",
            p.display(),
            install_commands(normal_core.as_deref(), LINUX_CORE_DIR).join("\n  ")
        ),
        Problem::NoTunDevice => {
            "Нет /dev/net/tun. Загрузите модуль: sudo modprobe tun (или включите поддержку TUN в ядре/контейнере).".into()
        }
        Problem::MissingWintun(p) => format!(
            "Для режима TUN нужен wintun.dll рядом с xray.exe: {} не найден. Он лежит в официальном архиве Xray (Xray-windows-64.zip).",
            p.display()
        ),
        Problem::UntrustedCore { path, reason } => format!(
            "Ядро для режима TUN {} небезопасно: {reason}. Запускать с повышенными правами можно только копию, которую никто кроме root не может изменить.\n\nУстановка (выполните сами):\n  {}",
            path.display(),
            install_commands(normal_core.as_deref(), LINUX_CORE_DIR).join("\n  ")
        ),
        Problem::NeedsPrivileges if cfg!(windows) => {
            "Режиму TUN нужны права администратора. Перезапустить elf-gate с правами администратора?".into()
        }
        Problem::NeedsPrivileges => format!(
            "У Xray нет прав создавать TUN-интерфейс.\n\nОднократно выполните:\n  sudo setcap cap_net_admin+ep {LINUX_CORE_DIR}/xray\nлибо запустите  sudo elf-gate  (конфиг останется в вашей домашней папке)."
        ),
        Problem::RpFilterStrict(rp) => format!(
            "Предупреждение: на интерфейсе {iface} включён строгий rp_filter (1). Трафик «напрямую» через TUN может зависать.\nПроверьте и, если нужно, выполните сами:\n  sudo sysctl -w net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.{iface}.rp_filter=2\nelf-gate эти настройки не меняет.",
            iface = rp.interface
        ),
    }
}

/// An Xray start error that really means "no rights".
pub fn looks_like_missing_privileges(error_text: &str) -> bool {
    let t = error_text.to_lowercase();
    t.contains("operation not permitted")
        || t.contains("access is denied")
        || t.contains("required privilege")
}

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
        cfg!(windows),
    );
    let tun = (traffic == TrafficMode::Tun).then(|| TunPlan {
        name: config.tun.name.clone(),
        ipv6: host.ipv6_enabled(),
        windows: cfg!(windows),
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
    .map_err(|_| format!("не удалось определить адрес {address}: таймаут DNS"))?
    .map_err(|e| format!("не удалось определить адрес {address}: {e}"))?
    .collect::<Vec<_>>();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .map(|a| a.ip())
        .ok_or_else(|| format!("для {address} нет адресов"))
}

/// Is the server reachable over TCP at all? Must run before the tunnel is up: afterwards
/// this machine's own connections would go through the tunnel.
pub async fn tcp_reachable(ip: IpAddr, port: u16, limit: Duration) -> Result<(), String> {
    match timeout(limit, TcpStream::connect((ip, port))).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("{ip}:{port} недоступен: {e}")),
        Err(_) => Err(format!(
            "{ip}:{port} недоступен: таймаут {} с",
            limit.as_secs()
        )),
    }
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
        (true, false) => format!("остановлен Xray от прошлого запуска, интерфейс {} убран", tun.interface),
        (true, true) => format!("остановлен Xray от прошлого запуска, но интерфейс {} ещё виден (должен исчезнуть сам)", tun.interface),
        (false, true) => format!("интерфейс {} остался от прошлого запуска, а процесс уже не найден: удалите его вручную (ip link del {})", tun.interface, tun.interface),
        (false, false) => "следов прошлого TUN-запуска не осталось (всё уже убрано)".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::mock::MockTunHost;
    use crate::storage::{Config, StateStore};

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("elf-gate-tun-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A config whose TUN core points at a real (empty) file.
    fn config_with_core(dir: &Path) -> Config {
        let core = dir.join("xray");
        std::fs::write(&core, b"x").unwrap();
        let mut c = Config::default();
        c.tun.xray_path = core.display().to_string();
        c
    }

    #[test]
    fn healthy_host_gives_a_setup() {
        let dir = temp_dir("ok");
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
        let dir = temp_dir("problems");
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
        if cfg!(windows) {
            // Windows has no root-owned copy: the core just has to sit next to elf-gate.exe.
            assert!(
                text.contains("xray.exe") && text.contains("рядом с elf-gate.exe"),
                "{text}"
            );
        } else {
            assert!(
                text.contains("sudo install") && text.contains("setcap cap_net_admin+ep"),
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
        let dir = temp_dir("rp");
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
        let dir = temp_dir("sup");
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
    fn privilege_errors_are_recognised() {
        assert!(looks_like_missing_privileges("Failed to start: app/proxyman/inbound: failed to start proxy > operation not permitted"));
        assert!(looks_like_missing_privileges("Access is denied."));
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
        assert!(err.contains("недоступен"), "{err}");
    }

    #[test]
    fn cleanup_kills_a_stale_core_and_clears_the_state() {
        let dir = temp_dir("stale");
        let store = StateStore::new(&dir);
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
        let dir = temp_dir("stale-iface");
        let store = StateStore::new(&dir);
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
        assert!(cmds[3].starts_with("sudo setcap cap_net_admin+ep"));
        assert!(cmds.iter().all(|c| c.starts_with("sudo ")));
    }
}
