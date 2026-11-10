//! Tests that need a real Xray binary: `XRAY_PATH`, else `bin/xray` (`bin/xray.exe` on
//! Windows). Without a binary every test here prints `SKIPPED` and returns, so CI stays
//! green. (libtest cannot mark a test as ignored at run time.)

use super::config;
use super::process::{Core, CoreError};
use crate::parser::parse_link;
use crate::parser::vless::xray_allows_plain_vless;
use crate::storage::CoreConfig;
use serde_json::{json, Value};
use std::net::TcpListener as StdListener;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::mpsc::unbounded_channel;
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

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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

/// The parser's address rule must agree with the installed Xray.
#[test]
fn address_rule_matches_installed_xray() {
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
        "example.com",
        "localhost",
        "myserver",
        "foo.local",
        "foo.lan",
        "foo.internal",
        "foo.test",
        "foo.localdomain",
        "foo.home.arpa",
        "foo.example",
        "foo.invalid",
        "foo.dev",
        "foo.corp",
        "foo.intranet",
        "foo.onion",
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
            xray_allows_plain_vless(addr),
            "parser and Xray disagree on {addr}: {out}"
        );
    }
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
    let server = parse_link(&format!("vless://{UUID}@127.0.0.1:1?security=none#dummy")).unwrap();
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
