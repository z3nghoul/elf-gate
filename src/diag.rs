//! The "Check" screen: one list of checks that run in turn, each with a state and, for a
//! problem, one line saying what to do. The checks ask [`Env`] for facts and decide nothing
//! about the system themselves, so every check is tested on a mock. The real `Env` is in
//! `engine::diag`; the report for the clipboard is [`report`].

use crate::tun::Problem;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckId {
    Core,
    Geodata,
    ServerTcp,
    ServerUrl,
    Dns,
    TunRights,
    Wintun,
    Firewall,
    Adapter,
    SysProxy,
    VpnIp,
    RuDirect,
}

impl CheckId {
    /// In the order they run and are shown.
    pub const ALL: [CheckId; 12] = [
        CheckId::Core,
        CheckId::Geodata,
        CheckId::ServerTcp,
        CheckId::ServerUrl,
        CheckId::Dns,
        CheckId::TunRights,
        CheckId::Wintun,
        CheckId::Firewall,
        CheckId::Adapter,
        CheckId::SysProxy,
        CheckId::VpnIp,
        CheckId::RuDirect,
    ];

    fn key(self) -> &'static str {
        match self {
            CheckId::Core => "core",
            CheckId::Geodata => "geodata",
            CheckId::ServerTcp => "server_tcp",
            CheckId::ServerUrl => "server_url",
            CheckId::Dns => "dns",
            CheckId::TunRights => "tun_rights",
            CheckId::Wintun => "wintun",
            CheckId::Firewall => "firewall",
            CheckId::Adapter => "adapter",
            CheckId::SysProxy => "sysproxy",
            CheckId::VpnIp => "vpn_ip",
            CheckId::RuDirect => "ru_direct",
        }
    }

    pub fn title(self) -> String {
        crate::i18n::tr(
            crate::i18n::current(),
            &format!("diag.title.{}", self.key()),
            &[],
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    Waiting,
    Running,
    Ok,
    Problem,
    Skipped,
}

impl State {
    pub fn label(self) -> String {
        let key = match self {
            State::Waiting => "waiting",
            State::Running => "running",
            State::Ok => "ok",
            State::Problem => "problem",
            State::Skipped => "skipped",
        };
        crate::i18n::tr(crate::i18n::current(), &format!("diag.state.{key}"), &[])
    }

    pub fn finished(self) -> bool {
        matches!(self, State::Ok | State::Problem | State::Skipped)
    }
}

/// What the screen may do about a problem. Only on an explicit press and after a question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Fix {
    /// Put the user's own system proxy settings back.
    ClearProxy,
    /// Remove the TUN adapter an earlier run left behind (Windows).
    RemoveAdapter,
    /// The one elevated firewall setup (UAC, Windows).
    ConfigureFirewall,
    /// Ping by a plain TCP connect: Xray is not there for the URL ping.
    PingToTcp,
}

impl Fix {
    pub fn question(self) -> String {
        let key = match self {
            Fix::ClearProxy => "clear_proxy",
            Fix::RemoveAdapter => "remove_adapter",
            Fix::ConfigureFirewall => "configure_firewall",
            Fix::PingToTcp => "ping_to_tcp",
        };
        crate::i18n::tr(crate::i18n::current(), &format!("diag.fix.{key}"), &[])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: CheckId,
    pub state: State,
    /// What was found. Never a server address or a key.
    pub detail: String,
    /// One line: what to do (a problem only).
    pub todo: Option<String>,
    pub fix: Option<Fix>,
}

impl CheckResult {
    pub fn waiting(id: CheckId) -> Self {
        Self::new(id, State::Waiting, String::new())
    }

    fn new(id: CheckId, state: State, detail: String) -> Self {
        Self {
            id,
            state,
            detail,
            todo: None,
            fix: None,
        }
    }

    fn ok(id: CheckId, detail: String) -> Self {
        Self::new(id, State::Ok, detail)
    }

    fn skipped(id: CheckId, why: String) -> Self {
        Self::new(id, State::Skipped, why)
    }

    fn problem(id: CheckId, detail: String, todo: String) -> Self {
        Self {
            todo: Some(todo),
            ..Self::new(id, State::Problem, detail)
        }
    }

    fn with_fix(mut self, fix: Fix) -> Self {
        self.fix = Some(fix);
        self
    }
}

/// Why a TCP connect to the server failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpFail {
    /// This machine refused it (10013 / access denied): the server was never asked.
    Blocked,
    Timeout {
        secs: u64,
    },
    Other(String),
}

/// How the system proxy settings relate to elf-gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyView {
    /// This desktop has no proxy settings elf-gate can read.
    Unsupported,
    /// Off, or pointing somewhere else.
    NotOurs,
    /// Pointing at the local ports of elf-gate.
    Ours { socks: u16, http: u16 },
}

/// The facts the checks need. Each call is one look at the system or the network.
#[allow(async_fn_in_trait)]
pub trait Env {
    fn windows(&self) -> bool;
    /// The core binary of the current mode (in TUN mode: the "Xray for TUN"), or the text
    /// saying where it was looked for.
    fn core_binary(&self) -> Result<PathBuf, String>;
    /// In TUN mode with a separate TUN core (Linux): the normal core, to compare versions.
    fn other_core(&self) -> Option<PathBuf>;
    /// The file capabilities of the core as `getcap` prints them; `None` when unknown.
    fn core_capabilities(&self, core: &Path) -> Option<String>;
    async fn core_version(&self, core: &Path) -> Result<String, String>;
    /// `(geoip.dat, geosite.dat)` present next to the core.
    fn geodata(&self, core: &Path) -> (bool, bool);
    /// The ping mode is "url" (it needs Xray).
    fn ping_is_url(&self) -> bool;
    /// Is there a server to test (the selected one, else the connected one)?
    fn has_server(&self) -> bool;
    async fn tcp(&self) -> Result<u32, TcpFail>;
    async fn url_ping(&self) -> Result<u32, String>;
    async fn dns_direct(&self, host: &str) -> bool;
    /// Resolved on the far side of the live connection; `None` without one.
    async fn dns_via_server(&self, host: &str) -> Option<bool>;
    fn tun_problems(&self) -> Vec<Problem>;
    fn explain(&self, problem: &Problem) -> String;
    /// `None` where there is no firewall to configure; `Err` when its rules cannot be read.
    fn firewall_rules_in_place(&self) -> Option<Result<bool, String>>;
    /// `Some(name)`: an adapter of ours is left although no TUN core runs (Windows only).
    fn stale_adapter(&self) -> Option<String>;
    fn proxy_view(&self) -> ProxyView;
    /// Our core process is running.
    fn core_running(&self) -> bool;
    fn connected(&self) -> bool;
    /// The `ru-direct` preset is on.
    fn ru_direct_on(&self) -> bool;
    async fn ip_via_vpn(&self) -> Result<String, String>;
    async fn ip_russian_site(&self) -> Result<String, String>;
}

const DNS_FOREIGN: [&str; 2] = ["cloudflare.com", "wikipedia.org"];
const DNS_RUSSIAN: [&str; 2] = ["yandex.ru", "vk.com"];

fn skip_text(key: &str) -> String {
    crate::i18n::tr(crate::i18n::current(), &format!("diag.skip.{key}"), &[])
}

/// Runs every check in turn and hands each one to `emit` twice: `Running`, then the result.
pub async fn run<E: Env>(env: &E, mut emit: impl FnMut(CheckResult)) {
    let mut vpn_ip: Option<String> = None;
    let mut core: Option<PathBuf> = None;
    for id in CheckId::ALL {
        emit(CheckResult::new(id, State::Running, String::new()));
        let result = match id {
            CheckId::Core => {
                let (result, found) = check_core(env).await;
                core = found;
                result
            }
            CheckId::Geodata => check_geodata(env, core.as_deref()),
            CheckId::ServerTcp => check_tcp(env).await,
            CheckId::ServerUrl => check_url(env, core.is_some()).await,
            CheckId::Dns => check_dns(env).await,
            CheckId::TunRights => check_tun_rights(env),
            CheckId::Wintun => check_wintun(env),
            CheckId::Firewall => check_firewall(env),
            CheckId::Adapter => check_adapter(env),
            CheckId::SysProxy => check_proxy(env),
            CheckId::VpnIp => {
                let (result, ip) = check_vpn(env).await;
                vpn_ip = ip;
                result
            }
            CheckId::RuDirect => check_ru(env, vpn_ip.as_deref()).await,
        };
        emit(result);
    }
}

async fn check_core<E: Env>(env: &E) -> (CheckResult, Option<PathBuf>) {
    let id = CheckId::Core;
    let path = match env.core_binary() {
        Ok(p) => p,
        Err(looked) => {
            let mut r = CheckResult::problem(
                id,
                crate::t!("diag.core_missing", looked = looked),
                crate::t!("diag.todo_core"),
            );
            if env.ping_is_url() {
                r.todo = Some(crate::t!("diag.todo_core_ping"));
                r.fix = Some(Fix::PingToTcp);
            }
            return (r, None);
        }
    };
    let version = match env.core_version(&path).await {
        Ok(v) => v,
        Err(e) => {
            return (
                CheckResult::problem(
                    id,
                    crate::t!("diag.core_broken", error = e),
                    crate::t!("diag.todo_core_broken"),
                ),
                None,
            )
        }
    };
    let shown = crate::redact::strip_home(&path.display().to_string());
    let Some(other) = env.other_core() else {
        return (
            CheckResult::ok(
                id,
                crate::t!("diag.core_ok", version = version, path = shown),
            ),
            Some(path),
        );
    };
    // TUN mode: the core that runs is the privileged copy; the normal one is only compared.
    let main_version = env
        .core_version(&other)
        .await
        .unwrap_or_else(|_| "?".into());
    let result = if main_version != "?" && main_version != version {
        CheckResult::problem(
            id,
            crate::t!(
                "diag.core_tun_differs",
                tun = version,
                main = main_version,
                path = shown
            ),
            crate::t!("diag.todo_core_tun_update"),
        )
    } else if env
        .core_capabilities(&path)
        .is_some_and(|caps| !caps.contains("cap_net_admin"))
    {
        CheckResult::problem(
            id,
            crate::t!("diag.core_tun_no_caps", version = version, path = shown),
            crate::t!("diag.todo_tun_linux"),
        )
    } else {
        CheckResult::ok(
            id,
            crate::t!(
                "diag.core_ok_tun",
                tun = version,
                main = main_version,
                path = shown
            ),
        )
    };
    (result, Some(path))
}

fn check_geodata<E: Env>(env: &E, core: Option<&Path>) -> CheckResult {
    let id = CheckId::Geodata;
    let Some(core) = core else {
        return CheckResult::skipped(id, skip_text("no_core"));
    };
    let (ip, site) = env.geodata(core);
    let missing: Vec<&str> = [(ip, "geoip.dat"), (site, "geosite.dat")]
        .into_iter()
        .filter(|(have, _)| !have)
        .map(|(_, name)| name)
        .collect();
    if missing.is_empty() {
        CheckResult::ok(id, crate::t!("diag.geo_ok"))
    } else {
        CheckResult::problem(
            id,
            crate::t!("diag.geo_missing", files = missing.join(", ")),
            crate::t!("diag.todo_geo"),
        )
    }
}

async fn check_tcp<E: Env>(env: &E) -> CheckResult {
    let id = CheckId::ServerTcp;
    if !env.has_server() {
        return CheckResult::skipped(id, skip_text("no_server"));
    }
    match env.tcp().await {
        Ok(ms) => CheckResult::ok(id, crate::t!("diag.tcp_ok", ms = ms)),
        Err(TcpFail::Blocked) => {
            let windows = env.windows();
            let mut r = CheckResult::problem(
                id,
                crate::t!("diag.tcp_blocked"),
                if windows {
                    crate::t!("diag.todo_tcp_blocked_windows")
                } else {
                    crate::t!("diag.todo_tcp_blocked")
                },
            );
            if windows {
                r.fix = Some(Fix::ConfigureFirewall);
            }
            r
        }
        Err(TcpFail::Timeout { secs }) => CheckResult::problem(
            id,
            crate::t!("diag.tcp_timeout", secs = secs),
            crate::t!("diag.todo_tcp"),
        ),
        Err(TcpFail::Other(e)) => CheckResult::problem(
            id,
            crate::t!("diag.tcp_failed", error = e),
            crate::t!("diag.todo_tcp"),
        ),
    }
}

async fn check_url<E: Env>(env: &E, have_core: bool) -> CheckResult {
    let id = CheckId::ServerUrl;
    if !have_core {
        return CheckResult::skipped(id, skip_text("no_core"));
    }
    if !env.has_server() {
        return CheckResult::skipped(id, skip_text("no_server"));
    }
    match env.url_ping().await {
        Ok(ms) => CheckResult::ok(id, crate::t!("diag.url_ok", ms = ms)),
        Err(e) => CheckResult::problem(
            id,
            crate::t!("diag.url_failed", error = e),
            crate::t!("diag.todo_url"),
        ),
    }
}

async fn resolved<E: Env>(env: &E, hosts: &[&str]) -> usize {
    let mut n = 0;
    for h in hosts {
        n += usize::from(env.dns_direct(h).await);
    }
    n
}

async fn check_dns<E: Env>(env: &E) -> CheckResult {
    let id = CheckId::Dns;
    let foreign = resolved(env, &DNS_FOREIGN).await;
    let russian = resolved(env, &DNS_RUSSIAN).await;
    let mut via_ok = 0;
    let mut via_total = 0;
    for h in DNS_FOREIGN.iter().chain(DNS_RUSSIAN.iter()) {
        if let Some(ok) = env.dns_via_server(h).await {
            via_total += 1;
            via_ok += usize::from(ok);
        }
    }
    let via = if via_total == 0 {
        crate::t!("diag.dns_not_connected")
    } else {
        format!("{via_ok}/{via_total}")
    };
    let detail = crate::t!(
        "diag.dns_detail",
        foreign = format!("{foreign}/{}", DNS_FOREIGN.len()),
        russian = format!("{russian}/{}", DNS_RUSSIAN.len()),
        via = via
    );
    if foreign == 0 && russian == 0 {
        CheckResult::problem(id, detail, crate::t!("diag.todo_dns"))
    } else if via_total > 0 && via_ok == 0 {
        CheckResult::problem(id, detail, crate::t!("diag.todo_dns_via"))
    } else {
        CheckResult::ok(id, detail)
    }
}

fn check_tun_rights<E: Env>(env: &E) -> CheckResult {
    let id = CheckId::TunRights;
    let problems = env.tun_problems();
    if problems
        .iter()
        .any(|p| matches!(p, Problem::CoreMissing(_)))
    {
        return CheckResult::skipped(id, skip_text("no_core"));
    }
    let relevant = problems.iter().find(|p| {
        matches!(
            p,
            Problem::NeedsPrivileges | Problem::NoTunDevice | Problem::UntrustedCore { .. }
        )
    });
    match relevant {
        None => CheckResult::ok(id, crate::t!("diag.tun_ok")),
        Some(p) => CheckResult::problem(
            id,
            env.explain(p)
                .lines()
                .next()
                .unwrap_or_default()
                .to_string(),
            if env.windows() {
                crate::t!("diag.todo_tun_windows")
            } else {
                crate::t!("diag.todo_tun_linux")
            },
        ),
    }
}

fn check_wintun<E: Env>(env: &E) -> CheckResult {
    let id = CheckId::Wintun;
    if !env.windows() {
        return CheckResult::skipped(id, skip_text("windows_only"));
    }
    let problems = env.tun_problems();
    if problems
        .iter()
        .any(|p| matches!(p, Problem::CoreMissing(_)))
    {
        return CheckResult::skipped(id, skip_text("no_core"));
    }
    if problems
        .iter()
        .any(|p| matches!(p, Problem::MissingWintun(_)))
    {
        CheckResult::problem(
            id,
            crate::t!("diag.wintun_missing"),
            crate::t!("diag.todo_wintun"),
        )
    } else {
        CheckResult::ok(id, crate::t!("diag.wintun_ok"))
    }
}

fn check_firewall<E: Env>(env: &E) -> CheckResult {
    let id = CheckId::Firewall;
    if !env.windows() {
        return CheckResult::skipped(id, skip_text("windows_only"));
    }
    match env.firewall_rules_in_place() {
        None => CheckResult::skipped(id, skip_text("windows_only")),
        Some(Ok(true)) => CheckResult::ok(id, crate::t!("diag.fw_ok")),
        Some(Ok(false)) => {
            CheckResult::problem(id, crate::t!("diag.fw_missing"), crate::t!("diag.todo_fw"))
                .with_fix(Fix::ConfigureFirewall)
        }
        Some(Err(e)) => CheckResult::problem(
            id,
            crate::t!("diag.fw_read", error = e),
            crate::t!("diag.todo_fw"),
        ),
    }
}

fn check_adapter<E: Env>(env: &E) -> CheckResult {
    let id = CheckId::Adapter;
    if !env.windows() {
        return CheckResult::skipped(id, skip_text("windows_only"));
    }
    match env.stale_adapter() {
        None => CheckResult::ok(id, crate::t!("diag.adapter_ok")),
        Some(name) => CheckResult::problem(
            id,
            crate::t!("diag.adapter_stale", name = name),
            crate::t!("diag.todo_adapter"),
        )
        .with_fix(Fix::RemoveAdapter),
    }
}

fn check_proxy<E: Env>(env: &E) -> CheckResult {
    let id = CheckId::SysProxy;
    match env.proxy_view() {
        ProxyView::Unsupported => CheckResult::skipped(id, skip_text("no_proxy_settings")),
        ProxyView::NotOurs => CheckResult::ok(id, crate::t!("diag.proxy_off")),
        ProxyView::Ours { socks, http } if env.core_running() => {
            CheckResult::ok(id, crate::t!("diag.proxy_ours", socks = socks, http = http))
        }
        ProxyView::Ours { .. } => CheckResult::problem(
            id,
            crate::t!("diag.proxy_left"),
            crate::t!("diag.todo_proxy"),
        )
        .with_fix(Fix::ClearProxy),
    }
}

async fn check_vpn<E: Env>(env: &E) -> (CheckResult, Option<String>) {
    let id = CheckId::VpnIp;
    if !env.connected() {
        return (CheckResult::skipped(id, skip_text("not_connected")), None);
    }
    match env.ip_via_vpn().await {
        Ok(ip) => (
            CheckResult::ok(id, crate::t!("diag.vpn_ok", ip = ip)),
            Some(ip),
        ),
        Err(e) => (
            CheckResult::problem(
                id,
                crate::t!("diag.vpn_failed", error = e),
                crate::t!("diag.todo_vpn"),
            ),
            None,
        ),
    }
}

async fn check_ru<E: Env>(env: &E, vpn_ip: Option<&str>) -> CheckResult {
    let id = CheckId::RuDirect;
    if !env.connected() {
        return CheckResult::skipped(id, skip_text("not_connected"));
    }
    if !env.ru_direct_on() {
        return CheckResult::skipped(id, skip_text("no_ru_preset"));
    }
    match env.ip_russian_site().await {
        Ok(ip) if Some(ip.as_str()) == vpn_ip => {
            CheckResult::problem(id, crate::t!("diag.ru_same"), crate::t!("diag.todo_ru"))
        }
        Ok(ip) => CheckResult::ok(id, crate::t!("diag.ru_ok", ip = ip)),
        Err(e) => CheckResult::problem(
            id,
            crate::t!("diag.ru_failed", error = e),
            crate::t!("diag.todo_ru"),
        ),
    }
}

/// A configured server as the report knows it.
pub struct ReportServer {
    pub name: String,
    pub address: String,
}

/// What the report holds besides the results.
pub struct ReportInput<'a> {
    pub version_line: String,
    pub os: String,
    pub mode: String,
    pub presets: Vec<String>,
    /// The configured servers: address and name both become "server 1", "server 2".
    pub servers: Vec<ReportServer>,
    /// The last lines of the log, as the interface has them.
    pub log: Vec<String>,
    pub results: &'a [CheckResult],
}

/// The report text for the clipboard. Server addresses turn into `server N`; links, URLs, ids
/// and keys go through the one place that hides secrets ([`crate::redact`]), and so does every
/// remaining address and name: what a log says about visited sites is private too.
pub fn report(input: &ReportInput<'_>) -> String {
    let mut lines = vec![
        input.version_line.clone(),
        format!("OS: {}", input.os),
        format!("{}: {}", crate::t!("diag.report_mode"), input.mode),
        format!(
            "{}: {}",
            crate::t!("diag.report_presets"),
            if input.presets.is_empty() {
                "-".to_string()
            } else {
                input.presets.join(", ")
            }
        ),
        String::new(),
    ];
    for r in input.results {
        lines.push(format!(
            "[{}] {}: {}",
            r.state.label(),
            r.id.title(),
            r.detail
        ));
        if let Some(todo) = &r.todo {
            lines.push(format!("    -> {todo}"));
        }
    }
    lines.push(String::new());
    lines.push(format!("{}:", crate::t!("diag.report_log")));
    lines.extend(input.log.iter().cloned());
    // Links go first: an address replaced inside a link would leave the rest of it readable.
    let mut text = crate::redact::secrets(&lines.join("\n"));
    // The number of a server is the place of its address in the list (equal addresses share it).
    let mut seen: Vec<&str> = Vec::new();
    let mut words: Vec<(&str, usize)> = Vec::new();
    for s in &input.servers {
        let n = match seen.iter().position(|a| *a == s.address) {
            Some(i) => i + 1,
            None => {
                seen.push(&s.address);
                seen.len()
            }
        };
        words.push((&s.address, n));
        words.push((&s.name, n));
    }
    // Longest first, so a name that contains an address (or the other way round) goes whole.
    words.retain(|(w, _)| w.chars().count() >= 3);
    words.sort_by_key(|(w, _)| std::cmp::Reverse(w.len()));
    words.dedup_by(|a, b| a.0 == b.0);
    for (word, n) in words {
        text = text.replace(word, &crate::t!("diag.report_server", n = n));
    }
    crate::redact::text(&text, crate::redact::Mode::Full)
}

#[cfg(test)]
mod tests;
