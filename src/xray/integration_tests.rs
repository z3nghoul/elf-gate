//! Tests that need a real Xray binary: `XRAY_PATH`, else `bin/xray` (`bin/xray.exe` on
//! Windows). Without a binary every test here prints `SKIPPED` and returns, so CI stays
//! green. (libtest cannot mark a test as ignored at run time.)

use super::config;
use super::process::{Core, CoreError};
use super::validate::Verdict;
use crate::engine::Engine;
use crate::event::BgEvent;
use crate::parser::parse_link;
use crate::parser::vless::plain_vless_blocked_for_ip;
use crate::platform::mock::{MockProxy, SharedMock};
use crate::proto::{Cmd, Conn};
use crate::storage::CoreConfig;
use crate::storage::{Config, ProxyConfig, StateStore};
use crate::sysproxy::{ProxyController, ProxyHandle};
use serde_json::{json, Value};
use std::net::TcpListener as StdListener;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::{sleep, timeout, Instant};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn xray_bin() -> Option<PathBuf> {
    if let Some(p) = std::env::var("XRAY_PATH").ok().filter(|v| !v.is_empty()) {
        let p = PathBuf::from(p);
        assert!(
            p.is_file(),
            "XRAY_PATH is set but is not a file: {}",
            p.display()
        );
        return Some(p);
    }
    let fallback = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("bin")
        .join(format!("xray{}", std::env::consts::EXE_SUFFIX));
    fallback.is_file().then_some(fallback)
}

macro_rules! require_xray {
    () => {
        match xray_bin() {
            Some(p) => p,
            None => {
                eprintln!("SKIPPED: set XRAY_PATH or put the binary at bin/xray");
                return;
            }
        }
    };
}

/// A unique temp directory removed on drop (also while a panic unwinds).
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("elf-gate-it-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Next port to try. Tests run in parallel, and ports from `bind(0)` come from the ephemeral
/// range that outgoing connections of other tests use as source ports, so they collide
/// now and then. Test ports are therefore taken from a range below it, each issued once.
static NEXT_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

fn free_port() -> u16 {
    use std::sync::atomic::Ordering;
    const BASE: u16 = 20_000;
    const SPAN: u16 = 10_000; // 20000..30000, below Linux's 32768.. ephemeral range
    loop {
        let n = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        // Spread processes apart so two test runs at once do not walk the same sequence.
        let offset = (std::process::id() as u16).wrapping_mul(97).wrapping_add(n) % SPAN;
        let port = BASE + offset;
        // Probe with a connect, never with bind: `TcpListener::bind` also listens, and when
        // another test thread forks a child (spawning xray) at that moment, the child keeps
        // the listening socket until it execs, so the very next bind of this port fails.
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err() {
            return port;
        }
    }
}

async fn wait_port(port: u16, open: bool, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        let is_open = TcpStream::connect(("127.0.0.1", port)).await.is_ok();
        if is_open == open {
            return true;
        }
        sleep(Duration::from_millis(50)).await;
    }
    false
}

/// `xray run -test -c <file>`; returns (success, stdout+stderr).
fn xray_test(xray: &Path, config: &Value, dir: &Path, name: &str) -> (bool, String) {
    let file = dir.join(format!("{name}.json"));
    std::fs::write(&file, serde_json::to_vec_pretty(config).unwrap()).unwrap();
    let out = StdCommand::new(xray)
        .args(["run", "-test", "-c"])
        .arg(&file)
        .env("XRAY_LOCATION_ASSET", xray.parent().unwrap())
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

/// Xray started as a throw-away local "server"; killed when dropped, even on panic.
struct ServerProc(#[allow(dead_code)] Child);

fn spawn_server(xray: &Path, config: &Value, dir: &Path) -> ServerProc {
    let file = dir.join("server.json");
    std::fs::write(&file, serde_json::to_vec_pretty(config).unwrap()).unwrap();
    let child = Command::new(xray)
        .args(["run", "-c"])
        .arg(&file)
        .env("XRAY_LOCATION_ASSET", xray.parent().unwrap())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    ServerProc(child)
}

// ---------------------------------------------------------------------------
// 1. Every snapshot config must be accepted by Xray.
// ---------------------------------------------------------------------------

/// Strips the insta front matter (`---\n...\n---\n`) from a `.snap` file.
fn snapshot_body(text: &str) -> &str {
    text.splitn(3, "---\n")
        .nth(2)
        .expect("snapshot without front matter")
}

#[test]
fn snapshot_configs_pass_xray_test() {
    let xray = require_xray!();
    let tmp = TempDir::new("snap");
    let snap_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/xray/snapshots");
    let mut checked = 0;
    let mut vnext_deprecated = false;
    for entry in std::fs::read_dir(&snap_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("snap") {
            continue;
        }
        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        let text = std::fs::read_to_string(&path).unwrap();
        let cfg: Value = serde_json::from_str(snapshot_body(&text)).unwrap();
        let (ok, out) = xray_test(&xray, &cfg, tmp.path(), &name);
        for line in out
            .lines()
            .filter(|l| l.to_lowercase().contains("deprecated"))
        {
            eprintln!("WARNING [{name}]: {line}");
            if line.to_lowercase().contains("vnext") {
                vnext_deprecated = true;
            }
        }
        assert!(ok, "xray rejected snapshot {name}:\n{out}");
        checked += 1;
    }
    assert!(
        checked >= 5,
        "expected at least 5 snapshot configs, found {checked}"
    );
    if vnext_deprecated {
        eprintln!("ATTENTION: Xray marks the VLESS `vnext` outbound form as deprecated");
    }
}

// ---------------------------------------------------------------------------
// 2. Unencrypted VLESS to a public address: Xray rejects it, the parser flags it.
// ---------------------------------------------------------------------------

#[test]
fn plain_vless_to_public_address_is_rejected_by_xray_and_flagged_by_parser() {
    let xray = require_xray!();
    let tmp = TempDir::new("plain");
    let mut server = parse_link(&format!(
        "vless://{UUID}@8.8.8.8:443?security=none&encryption=none&type=tcp#public"
    ))
    .unwrap();
    assert!(!server.is_supported(), "parser must flag the server");

    // Bypass our own guard to prove Xray itself refuses the config.
    server.unsupported = None;
    let cfg = config::build(&server, &CoreConfig::default()).unwrap();
    let (ok, out) = xray_test(&xray, &cfg, tmp.path(), "plain-public");
    assert!(
        !ok,
        "xray accepted unencrypted VLESS to a public IP:\n{out}"
    );
    assert!(out.contains("prohibited"), "{out}");

    // The same address with a real `encryption` is accepted.
    let enc = "mlkem768x25519plus.native.0rtt.45M6KAE8QF6VlzscrkIrjshB78IYPvGemYDCFrzFi14";
    let ok_server = parse_link(&format!(
        "vless://{UUID}@8.8.8.8:443?security=none&encryption={enc}&type=tcp#pq"
    ))
    .unwrap();
    assert!(ok_server.is_supported());
    let cfg = config::build(&ok_server, &CoreConfig::default()).unwrap();
    let (ok, out) = xray_test(&xray, &cfg, tmp.path(), "pq-public");
    assert!(ok, "{out}");
}

/// The parser's IP rule must agree with the installed Xray (IPs only; names are Xray's call).
#[test]
fn ip_rule_matches_installed_xray() {
    let xray = require_xray!();
    let tmp = TempDir::new("addr");
    for addr in [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "172.32.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "100.64.0.1",
        "8.8.8.8",
        "::1",
        "fd00::1",
        "fe80::1",
        "2001:db8::1",
    ] {
        let cfg = json!({
            "inbounds": [],
            "outbounds": [{
                "protocol": "vless",
                "settings": { "vnext": [{
                    "address": addr, "port": 443,
                    "users": [{ "id": UUID, "encryption": "none" }]
                }]},
                "streamSettings": { "network": "tcp", "security": "none" }
            }]
        });
        let (ok, out) = xray_test(&xray, &cfg, tmp.path(), "addr");
        assert_eq!(
            ok,
            !plain_vless_blocked_for_ip(addr),
            "parser and Xray disagree on {addr}: {out}"
        );
    }
}

/// Domains are judged by Xray through `validate::check`, not by a table in our code.
#[tokio::test]
async fn xray_validation_decides_domains() {
    let xray = require_xray!();
    let tmp = TempDir::new("domains");
    let core_cfg = CoreConfig {
        xray_path: xray.to_string_lossy().into_owned(),
        ..CoreConfig::default()
    };
    let check = |host: &str, query: &str| {
        let server = parse_link(&format!("vless://{UUID}@{host}:443?{query}#d")).unwrap();
        assert!(server.is_supported(), "the parser must not judge {host}");
        let dir = tmp.path().to_path_buf();
        let core_cfg = core_cfg.clone();
        async move {
            super::checkcache::Checker::new(None)
                .check(&core_cfg, &server, &dir)
                .await
        }
    };

    match check("example.com", "security=none").await {
        Verdict::Rejected(text) => assert!(text.contains("prohibited"), "{text}"),
        other => panic!("example.com without TLS must be rejected, got {other:?}"),
    }
    assert_eq!(check("vps1", "security=none").await, Verdict::Accepted);
    assert_eq!(
        check("example.com", "security=tls").await,
        Verdict::Accepted
    );
}

// ---------------------------------------------------------------------------
// 3. Full chain without external servers:
//    test client -> our Core -> local xray "server" -> local HTTP server.
// ---------------------------------------------------------------------------

async fn serve_http(listener: TcpListener) {
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let body = "elf-gate-chain-ok";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
    }
}

/// Minimal SOCKS5 client: CONNECT to 127.0.0.1:`target`, then a plain HTTP GET.
async fn socks_get(socks_port: u16, target: u16) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0], "socks method selection");
    let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
    req.extend(target.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "socks CONNECT failed, reply code {}", reply[1]);
    s.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut body = String::new();
    s.read_to_string(&mut body).await.unwrap();
    body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_reaches_http_server_through_local_vless_server() {
    let xray = require_xray!();
    let tmp = TempDir::new("chain");

    // Local "server": VLESS inbound on a free loopback port, no encryption, freedom out.
    let server_port = free_port();
    let access_log = tmp.path().join("server-access.log");
    let _server = spawn_server(
        &xray,
        &json!({
            "log": { "loglevel": "warning", "access": access_log },
            "inbounds": [{
                "listen": "127.0.0.1", "port": server_port, "protocol": "vless",
                "settings": { "clients": [{ "id": UUID }], "decryption": "none" },
                "streamSettings": { "network": "tcp", "security": "none" }
            }],
            // Xray 26.x: `freedom` fed by a VLESS inbound refuses loopback/private targets
            // by default ("blocked by a finalrule"); the test target lives on loopback.
            "outbounds": [{
                "protocol": "freedom",
                "settings": { "finalRules": [{ "action": "allow" }] }
            }]
        }),
        tmp.path(),
    );
    assert!(
        wait_port(server_port, true, 10).await,
        "local server did not start"
    );

    // Local HTTP target.
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http.local_addr().unwrap().port();
    tokio::spawn(serve_http(http));

    // Client config comes from our generator.
    let server = parse_link(&format!(
        "vless://{UUID}@127.0.0.1:{server_port}?security=none&type=tcp#local"
    ))
    .unwrap();
    assert!(server.is_supported());
    let core_cfg = CoreConfig {
        xray_path: xray.to_string_lossy().into_owned(),
        socks_port: free_port(),
        http_port: free_port(),
        ..CoreConfig::default()
    };
    let mut cfg = config::build(&server, &core_cfg).unwrap();
    // The target is on loopback, which the default `geoip:private -> direct` rule would
    // send around the proxy. Drop the rule so the traffic must use the VLESS chain.
    cfg["routing"]["rules"] = json!([]);

    let (tx, mut rx) = unbounded_channel();
    let core = Core::start(&core_cfg, &cfg, &tmp.path().join("run"), tx)
        .await
        .expect("client core failed to start");

    let response = timeout(
        Duration::from_secs(10),
        socks_get(core_cfg.socks_port, http_port),
    )
    .await
    .expect("request through the chain timed out");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("elf-gate-chain-ok"), "{response}");

    // The traffic really went through the server: its access log saw the target.
    let needle = format!("accepted tcp:127.0.0.1:{http_port}");
    let mut seen = false;
    for _ in 0..40 {
        if std::fs::read_to_string(&access_log).is_ok_and(|t| t.contains(&needle)) {
            seen = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(seen, "server access log has no `{needle}`");

    // Core output reaches the log channel.
    let mut lines = 0;
    while rx.try_recv().is_ok() {
        lines += 1;
    }
    assert!(lines > 0, "no log lines from the core");

    // Stop: the process is gone and the port is closed.
    assert!(core.pid().is_some());
    core.stop().await;
    assert!(
        wait_port(core_cfg.socks_port, false, 5).await,
        "socks port still open after stop"
    );
}

// ---------------------------------------------------------------------------
// 4. Core lifecycle edge cases.
// ---------------------------------------------------------------------------

fn dummy_client(xray: &Path) -> (CoreConfig, Value) {
    let server = parse_link(&format!("vless://{UUID}@127.0.0.1:2?security=none#dummy")).unwrap();
    let core_cfg = CoreConfig {
        xray_path: xray.to_string_lossy().into_owned(),
        socks_port: free_port(),
        http_port: free_port(),
        ..CoreConfig::default()
    };
    let cfg = config::build(&server, &core_cfg).unwrap();
    (core_cfg, cfg)
}

/// Dropping the handle (what happens while a test or the app panics) kills the process.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_core_kills_the_process() {
    let xray = require_xray!();
    let tmp = TempDir::new("drop");
    let (core_cfg, cfg) = dummy_client(&xray);
    let (tx, _rx) = unbounded_channel();
    let core = Core::start(&core_cfg, &cfg, tmp.path(), tx).await.unwrap();
    assert!(wait_port(core_cfg.socks_port, true, 2).await);
    drop(core);
    assert!(
        wait_port(core_cfg.socks_port, false, 5).await,
        "process survived the drop"
    );
}

/// A core that dies at startup yields an error that carries its output.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn core_that_exits_early_reports_its_output() {
    let xray = require_xray!();
    let tmp = TempDir::new("early");
    let core_cfg = CoreConfig {
        xray_path: xray.to_string_lossy().into_owned(),
        socks_port: free_port(),
        http_port: free_port(),
        ..CoreConfig::default()
    };
    let (tx, _rx) = unbounded_channel();
    let err = Core::start(
        &core_cfg,
        &json!({ "inbounds": "not-a-list" }),
        tmp.path(),
        tx,
    )
    .await
    .expect_err("broken config must fail");
    match err {
        CoreError::ExitedEarly { tail, .. } => {
            assert!(tail.to_lowercase().contains("fail"), "tail: {tail}");
        }
        other => panic!("expected ExitedEarly, got {other}"),
    }
}

/// Busy ports are reported before any process is spawned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn busy_port_blocks_start_before_spawning() {
    let xray = require_xray!();
    let tmp = TempDir::new("busy");
    let (core_cfg, cfg) = dummy_client(&xray);
    let _hog = StdListener::bind(("127.0.0.1", core_cfg.http_port)).unwrap();
    let (tx, _rx) = unbounded_channel();
    let err = Core::start(&core_cfg, &cfg, tmp.path(), tx)
        .await
        .unwrap_err();
    assert!(
        matches!(err, CoreError::PortBusy { what: "http", .. }),
        "{err}"
    );
}

// ---------------------------------------------------------------------------
// 5. System proxy wired to the real core (fake desktop, real Xray).
// ---------------------------------------------------------------------------

struct Rig {
    app: Engine,
    id: u64,
    rx: UnboundedReceiver<BgEvent>,
    desktop: Arc<MockProxy>,
    controller: Arc<ProxyController>,
    core_cfg: CoreConfig,
    _tmp: TempDir,
    /// The "VPS": something must listen, because connecting checks the server over TCP first.
    _vps: StdListener,
}

/// An app with one manual server pointing at a dead loopback port (the core starts fine,
/// it just has nowhere to forward), a fake desktop that has its own proxy configured,
/// and a proxy controller over it.
fn rig(xray: &Path, tag: &str, set_system_proxy: bool) -> Rig {
    let tmp = TempDir::new(tag);
    let core_cfg = CoreConfig {
        xray_path: xray.to_string_lossy().into_owned(),
        socks_port: free_port(),
        http_port: free_port(),
        ..CoreConfig::default()
    };
    let config = Config {
        core: core_cfg.clone(),
        proxy: ProxyConfig {
            set_system_proxy,
            ..ProxyConfig::default()
        },
        ..Config::default()
    };
    let desktop = Arc::new(MockProxy::with_user_settings(&[
        ("enabled", "1"),
        ("server", "corp-proxy:3128"),
        ("bypass", "*.corp"),
    ]));
    let controller = Arc::new(ProxyController::new(
        Box::new(SharedMock(desktop.clone())),
        StateStore::new(tmp.path().join("state")),
    ));
    let (tx, rx) = unbounded_channel();
    let mut app = Engine::build(tx.clone(), config, None, false)
        .with_run_dir(tmp.path().join("run"))
        .with_proxy(ProxyHandle::spawn(controller.clone(), tx));
    let vps = StdListener::bind("127.0.0.1:0").unwrap();
    let vps_port = vps.local_addr().unwrap().port();
    app.add_link(format!(
        "vless://{UUID}@127.0.0.1:{vps_port}?security=none#local"
    ));
    assert!(app.alerts().is_empty(), "{:?}", app.alerts());
    let id = app.subs.last().unwrap().servers[0].id; // the manual server
    Rig {
        app,
        id,
        rx,
        desktop,
        controller,
        core_cfg,
        _tmp: tmp,
        _vps: vps,
    }
}

/// Feeds background events (and ticks while idle) into the app until `done` holds.
async fn pump(
    app: &mut Engine,
    rx: &mut UnboundedReceiver<BgEvent>,
    done: impl Fn(&Engine) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !done(app) {
        assert!(
            Instant::now() < deadline,
            "timed out; conn={:?} alerts={:?} status={:?}",
            app.conn,
            app.alerts(),
            app.last_status()
        );
        match timeout(Duration::from_millis(250), rx.recv()).await {
            Ok(Some(ev)) => app.on_bg(ev),
            Ok(None) => panic!("event channel closed"),
            Err(_) => app.on_tick(),
        }
    }
}

fn connected(app: &Engine) -> bool {
    matches!(app.conn, Conn::Connected(_))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn system_proxy_follows_the_connection_and_restores_users_settings() {
    let xray = require_xray!();
    let mut r = rig(&xray, "sysproxy", true);
    let before = r.desktop.snapshot();

    r.app.handle_cmd(Cmd::Connect(r.id)); // connect
    pump(&mut r.app, &mut r.rx, |a| connected(a) && a.proxy_active).await;
    let during = r.desktop.snapshot();
    assert_eq!(
        during.values["server"],
        format!("127.0.0.1:{}", r.core_cfg.http_port)
    );
    assert!(r.controller.is_active());

    r.app.handle_cmd(Cmd::Disconnect);
    pump(&mut r.app, &mut r.rx, |a| !a.proxy_active).await;
    assert_eq!(
        r.desktop.snapshot(),
        before,
        "the user's own proxy must be back"
    );
    assert!(!r.controller.is_active());
    assert!(r.app.alerts().is_empty(), "{:?}", r.app.alerts());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quitting_restores_the_system_proxy() {
    let xray = require_xray!();
    let mut r = rig(&xray, "sysproxy-quit", true);
    let before = r.desktop.snapshot();

    r.app.handle_cmd(Cmd::Connect(r.id));
    pump(&mut r.app, &mut r.rx, |a| connected(a) && a.proxy_active).await;
    assert_ne!(r.desktop.snapshot(), before);

    r.app.shutdown().await;
    assert_eq!(r.desktop.snapshot(), before);
    assert!(!r.controller.is_active());
    assert!(
        wait_port(r.core_cfg.socks_port, false, 5).await,
        "core must be stopped too"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crashed_core_does_not_leave_a_dead_system_proxy() {
    let xray = require_xray!();
    let mut r = rig(&xray, "sysproxy-crash", true);
    let before = r.desktop.snapshot();

    r.app.handle_cmd(Cmd::Connect(r.id));
    pump(&mut r.app, &mut r.rx, |a| connected(a) && a.proxy_active).await;
    let pid = r.app.core_pid().expect("core pid");
    // Only the exact process this test started.
    let killed = StdCommand::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .unwrap();
    assert!(killed.success());

    pump(&mut r.app, &mut r.rx, |a| {
        matches!(a.conn, Conn::Error(_)) && !a.proxy_active
    })
    .await;
    assert_eq!(
        r.desktop.snapshot(),
        before,
        "a dead core must not keep the proxy on"
    );
    assert!(
        matches!(r.app.alerts().last(), Some(crate::proto::Alert::Error(_))),
        "the user must see the failure"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_desktop_gets_a_manual_hint_and_is_left_alone() {
    let xray = require_xray!();
    let mut r = rig(&xray, "sysproxy-unsupported", true);
    r.desktop
        .unsupported
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let before = r.desktop.snapshot();

    r.app.handle_cmd(Cmd::Connect(r.id));
    pump(&mut r.app, &mut r.rx, connected).await;
    let hint = r.app.last_status().expect("a hint must be shown");
    assert!(
        hint.contains(&format!("127.0.0.1:{}", r.core_cfg.socks_port)),
        "{hint}"
    );
    assert!(
        hint.contains(&format!("127.0.0.1:{}", r.core_cfg.http_port)),
        "{hint}"
    );
    assert!(hint.contains("TUN"), "{hint}");
    assert_eq!(r.desktop.snapshot(), before);
    assert!(!r.app.proxy_active);
    r.app.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_system_proxy_false_never_touches_the_system() {
    let xray = require_xray!();
    let mut r = rig(&xray, "sysproxy-off", false);
    let before = r.desktop.snapshot();

    r.app.handle_cmd(Cmd::Connect(r.id));
    pump(&mut r.app, &mut r.rx, connected).await;
    sleep(Duration::from_millis(500)).await; // give a wrongly queued command time to run
    assert_eq!(r.desktop.snapshot(), before);
    assert!(!r.controller.is_active());
    r.app.shutdown().await;
    assert_eq!(r.desktop.snapshot(), before);
}

#[tokio::test]
async fn repeated_checks_come_from_the_cache_and_a_new_version_drops_it() {
    use super::checkcache::{config_key, Checker};
    let xray = require_xray!();
    let dir = TempDir::new("checkcache");
    let cache_file = dir.path().join("check-cache.json");
    let server = parse_link(&format!(
        "vless://{UUID}@h.example.com:443?security=reality&sni=x.org&pbk=4GObrWHDR0TyD84iQ06z24v4YBxQ69vxeG1MCqOyFlI&sid=ab&fp=chrome#R"
    ))
    .unwrap();
    let core = CoreConfig {
        xray_path: xray.display().to_string(),
        ..CoreConfig::default()
    };
    let cfg = config::build(&server, &core).unwrap();

    let checker = Checker::new(Some(cache_file.clone()));
    assert_eq!(
        checker.check(&core, &server, dir.path()).await,
        Verdict::Accepted
    );
    checker.flush();
    let text = std::fs::read_to_string(&cache_file).unwrap();
    assert!(text.contains(&config_key(&cfg)), "{text}");

    // A new process (fresh Checker) answers from the file without starting Xray: a binary
    // path that does not exist for `xray run -test` still gets the cached verdict only if the
    // version lookup works, so check through the real binary but with the work dir missing.
    let again = Checker::new(Some(cache_file.clone()));
    let started = std::time::Instant::now();
    assert_eq!(
        again
            .check(&core, &server, &dir.path().join("no-such-dir"))
            .await,
        Verdict::Accepted
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "a cached verdict must not need a test run"
    );
    // The run directory was never created: nothing was executed.
    assert!(!dir.path().join("no-such-dir").exists());

    // Another version string wipes the cache.
    let mut raw = super::checkcache::CheckCache::load(Some(cache_file));
    raw.use_version("Xray 0.0.0-other");
    assert_eq!(raw.lookup(&config_key(&cfg)), None);
}

/// The URL ping starts a throw-away core, measures a request through its socks port and
/// cleans up after itself. (The target is on loopback, which the default rules send direct, so
/// this checks the probe machinery; the chain itself is covered by the test above.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn url_ping_runs_a_temporary_core_and_cleans_up() {
    use crate::model::server::Ping;
    use crate::net::ping::url_ping;
    use crate::storage::PingConfig;
    let xray = require_xray!();
    let tmp = TempDir::new("urlping");
    let server_port = free_port();
    let _server = spawn_server(
        &xray,
        &json!({
            "inbounds": [{
                "listen": "127.0.0.1", "port": server_port, "protocol": "vless",
                "settings": { "clients": [{ "id": UUID }], "decryption": "none" },
                "streamSettings": { "network": "tcp", "security": "none" }
            }],
            "outbounds": [{ "protocol": "freedom" }]
        }),
        tmp.path(),
    );
    assert!(wait_port(server_port, true, 10).await);
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http.local_addr().unwrap().port();
    tokio::spawn(serve_http(http));

    let server = parse_link(&format!(
        "vless://{UUID}@127.0.0.1:{server_port}?security=none&type=tcp#local"
    ))
    .unwrap();
    let core = CoreConfig {
        xray_path: xray.display().to_string(),
        ..CoreConfig::default()
    };
    let run_dir = tmp.path().join("run");
    let cfg = |url: String| PingConfig {
        url,
        timeout_ms: 4000,
        ..PingConfig::default()
    };

    let (ok, suspect) = url_ping(
        &xray,
        &core,
        &server,
        &cfg(format!("http://127.0.0.1:{http_port}/")),
        &run_dir,
    )
    .await;
    assert!(matches!(ok, Ping::Ms(_)), "{ok:?}");
    assert!(!suspect);

    // A URL that cannot be reached while the server itself answers over TCP: the caller is
    // told to try other fingerprints.
    let closed = free_port();
    let (bad, suspect) = url_ping(
        &xray,
        &core,
        &server,
        &cfg(format!("http://127.0.0.1:{closed}/")),
        &run_dir,
    )
    .await;
    assert!(matches!(bad, Ping::Error | Ping::Timeout), "{bad:?}");
    assert!(suspect, "TCP works, URL does not");

    // No probe config files are left behind.
    let leftovers: Vec<_> = std::fs::read_dir(&run_dir)
        .map(|d| d.flatten().map(|e| e.file_name()).collect())
        .unwrap_or_default();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

// ---------------------------------------------------------------------------
// Primary + backup: Xray's own observatory drives the switch.
// ---------------------------------------------------------------------------

fn local_vless_server_config(port: u16, access_log: &Path) -> Value {
    json!({
        "log": { "loglevel": "warning", "access": access_log },
        "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "vless",
            "settings": { "clients": [{ "id": UUID }], "decryption": "none" },
            "streamSettings": { "network": "tcp", "security": "none" }
        }],
        "outbounds": [{
            "protocol": "freedom",
            "settings": { "finalRules": [{ "action": "allow" }] }
        }]
    })
}

fn accepted_count(log: &Path, port: u16) -> usize {
    let needle = format!("accepted tcp:127.0.0.1:{port}");
    std::fs::read_to_string(log)
        .map(|t| t.matches(&needle).count())
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn traffic_moves_to_the_backup_when_the_primary_dies_and_returns_after_clean_probes() {
    use super::config::{Failover, Plan};
    use crate::model::rule::EffectiveRules;
    let xray = require_xray!();
    let tmp = TempDir::new("failover");

    let (p_port, b_port) = (free_port(), free_port());
    let (p_log, b_log) = (tmp.path().join("p.log"), tmp.path().join("b.log"));
    let (p_dir, b_dir) = (tmp.path().join("p"), tmp.path().join("b"));
    std::fs::create_dir_all(&p_dir).unwrap();
    std::fs::create_dir_all(&b_dir).unwrap();
    let mut primary_proc = Some(spawn_server(
        &xray,
        &local_vless_server_config(p_port, &p_log),
        &p_dir,
    ));
    let _backup_proc = spawn_server(&xray, &local_vless_server_config(b_port, &b_log), &b_dir);
    assert!(wait_port(p_port, true, 10).await && wait_port(b_port, true, 10).await);

    // `probe_port` is what the observatory fetches; `user_port` is what the test requests, so
    // the two kinds of traffic can be told apart in the servers' logs.
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let probe_port = probe.local_addr().unwrap().port();
    tokio::spawn(serve_http(probe));
    let user = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let user_port = user.local_addr().unwrap().port();
    tokio::spawn(serve_http(user));

    let link = |port: u16, name: &str| {
        parse_link(&format!(
            "vless://{UUID}@127.0.0.1:{port}?security=none&type=tcp#{name}"
        ))
        .unwrap()
    };
    let core_cfg = CoreConfig {
        xray_path: xray.display().to_string(),
        socks_port: free_port(),
        http_port: free_port(),
        ..CoreConfig::default()
    };
    let mut failover = Failover::new(
        link(b_port, "backup"),
        None,
        format!("http://127.0.0.1:{probe_port}/generate_204"),
    );
    failover.interval_secs = 1;
    let plan = Plan {
        failover: Some(failover),
        rules: EffectiveRules::default(),
        ..Plan::proxy_default()
    };
    let mut cfg = config::build_with(&link(p_port, "primary"), &core_cfg, &plan).unwrap();
    // The targets are on loopback: drop the "private networks go direct" rule.
    cfg["routing"]["rules"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r.get("ip").is_none());
    let (ok, text) = xray_test(&xray, &cfg, tmp.path(), "client");
    assert!(ok, "Xray rejects the failover config: {text}");

    let (tx, _rx) = unbounded_channel();
    let core = Core::start(&core_cfg, &cfg, &tmp.path().join("run"), tx)
        .await
        .expect("client core");

    // Which server saw the next user request?
    let who = |before: (usize, usize)| {
        let now = (
            accepted_count(&p_log, user_port),
            accepted_count(&b_log, user_port),
        );
        (now.0 > before.0, now.1 > before.1)
    };
    let counts = || {
        (
            accepted_count(&p_log, user_port),
            accepted_count(&b_log, user_port),
        )
    };
    let request = || async {
        let _ = timeout(
            Duration::from_secs(5),
            socks_get(core_cfg.socks_port, user_port),
        )
        .await;
    };

    // 1. Everything alive: the primary carries the traffic.
    sleep(Duration::from_secs(3)).await;
    let before = counts();
    request().await;
    sleep(Duration::from_millis(300)).await;
    assert_eq!(who(before), (true, false), "primary first");

    // 2. The primary dies: the backup takes over within a few probes.
    drop(primary_proc.take());
    assert!(wait_port(p_port, false, 5).await);
    let started = Instant::now();
    let mut switched = None;
    while started.elapsed() < Duration::from_secs(20) {
        let before = counts();
        request().await;
        sleep(Duration::from_millis(300)).await;
        if who(before) == (false, true) {
            switched = Some(started.elapsed());
            break;
        }
        sleep(Duration::from_millis(500)).await;
    }
    let switched = switched.expect("the backup never took over");
    eprintln!("failover took {switched:?}");

    // 3. The primary returns: traffic goes back, but not at the very first clean probe.
    primary_proc = Some(spawn_server(
        &xray,
        &local_vless_server_config(p_port, &p_log),
        &p_dir,
    ));
    assert!(wait_port(p_port, true, 10).await);
    let started = Instant::now();
    let mut back = None;
    while started.elapsed() < Duration::from_secs(40) {
        let before = counts();
        request().await;
        sleep(Duration::from_millis(300)).await;
        if who(before) == (true, false) {
            back = Some(started.elapsed());
            break;
        }
        sleep(Duration::from_millis(500)).await;
    }
    let back = back.expect("traffic never returned to the primary");
    eprintln!("return took {back:?}");
    drop(primary_proc);
    core.stop().await;
}

/// Traffic through the core shows up in `xray api statsquery` under the `proxy` outbound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn statsquery_counts_traffic_through_the_proxy_outbound() {
    use super::stats;
    let xray = require_xray!();
    let tmp = TempDir::new("stats");
    let server_port = free_port();
    let _server = spawn_server(
        &xray,
        &local_vless_server_config(server_port, &tmp.path().join("s.log")),
        tmp.path(),
    );
    assert!(wait_port(server_port, true, 10).await);
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http.local_addr().unwrap().port();
    tokio::spawn(serve_http(http));

    let server = parse_link(&format!(
        "vless://{UUID}@127.0.0.1:{server_port}?security=none&type=tcp#local"
    ))
    .unwrap();
    let core_cfg = CoreConfig {
        xray_path: xray.display().to_string(),
        socks_port: free_port(),
        http_port: free_port(),
        api_port: free_port(),
        ..CoreConfig::default()
    };
    let mut cfg = config::build(&server, &core_cfg).unwrap();
    // Keep only the api rule: the loopback target must go through the VLESS chain.
    cfg["routing"]["rules"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r.get("inboundTag").is_some());
    let (tx, _rx) = unbounded_channel();
    let core = Core::start(&core_cfg, &cfg, &tmp.path().join("run"), tx)
        .await
        .unwrap();
    let body = timeout(
        Duration::from_secs(10),
        socks_get(core_cfg.socks_port, http_port),
    )
    .await
    .unwrap();
    assert!(body.contains("elf-gate-chain-ok"));
    let c = stats::query(&xray, core_cfg.api_port)
        .await
        .expect("statsquery output");
    // (The uplink counter of a short request can still read 0 when it is queried.)
    assert!(c.proxy_down > 0 && c.direct_down == 0, "{c:?}");
    core.stop().await;
}

/// Complete provider configs (chains, a balancer) become configs that Xray accepts, with the
/// provider's gRPC and fragment outbounds carried over untouched.
#[test]
fn provider_chain_configs_pass_xray_test() {
    use crate::model::fullconfig::parse_entry;
    use crate::model::fullconfig::tests::fixtures;
    let xray = require_xray!();
    let tmp = TempDir::new("fullconfig");
    for (name, entry) in fixtures() {
        let server = parse_entry(&entry).unwrap();
        let cfg = config::build(&server, &CoreConfig::default()).unwrap();
        let (ok, text) = xray_test(&xray, &cfg, tmp.path(), name);
        assert!(ok, "{name}: {text}");
        // And in TUN with every name pinned to an address.
        let mut plan = config::Plan::proxy_default();
        for h in server.all_hosts() {
            plan.pin.insert(h, "203.0.113.10".into());
        }
        let cfg = config::build_with(&server, &CoreConfig::default(), &plan).unwrap();
        let (ok, text) = xray_test(&xray, &cfg, tmp.path(), &format!("{name}-pinned"));
        assert!(ok, "{name} pinned: {text}");
    }
}
