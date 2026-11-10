//! End to end: the real `elf-gated` binary in an isolated environment (own HOME, own socket,
//! no desktop, so the system proxy is never touched), driven over the local link.
#![cfg(unix)]

use elf_gate::proto::{decode, encode, Cmd, Conn, Update, View};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

struct Env {
    dir: PathBuf,
}

impl Env {
    fn new(tag: &str) -> Env {
        let dir = std::env::temp_dir().join(format!("elf-gate-e2e-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("run")).unwrap();
        Env { dir }
    }
    fn socket(&self) -> PathBuf {
        self.dir.join("run/elf-gate.sock")
    }
    fn config(&self, text: &str) {
        let d = self.dir.join("config/elf-gate");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("config.toml"), text).unwrap();
    }
    fn daemon(&self) -> Child {
        Command::new(env!("CARGO_BIN_EXE_elf-gated"))
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &self.dir)
            .env("XDG_CONFIG_HOME", self.dir.join("config"))
            .env("XDG_STATE_HOME", self.dir.join("state"))
            .env("XDG_RUNTIME_DIR", self.dir.join("run"))
            .env("ELF_GATE_SOCKET", self.socket())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_socket(path: &Path) -> UnixStream {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(s) = UnixStream::connect(path).await {
            return s;
        }
        assert!(Instant::now() < end, "daemon socket never appeared");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

struct Client {
    lines: tokio::io::Lines<BufReader<tokio::io::ReadHalf<UnixStream>>>,
    write: tokio::io::WriteHalf<UnixStream>,
    last: Option<View>,
}

impl Client {
    fn new(s: UnixStream) -> Client {
        let (r, w) = tokio::io::split(s);
        Client {
            lines: BufReader::new(r).lines(),
            write: w,
            last: None,
        }
    }
    async fn send(&mut self, cmd: Cmd) {
        self.write.write_all(encode(&cmd).as_bytes()).await.unwrap();
    }
    /// Reads updates until `pred` holds for the latest view.
    async fn until(&mut self, what: &str, pred: impl Fn(&View) -> bool) -> View {
        let end = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(v) = &self.last {
                if pred(v) {
                    return v.clone();
                }
            }
            let left = end.saturating_duration_since(Instant::now());
            let line = tokio::time::timeout(left, self.lines.next_line())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
                .unwrap()
                .unwrap_or_else(|| panic!("link closed while waiting for {what}"));
            if let Ok(Update::View(v)) = decode::<Update>(&line) {
                self.last = Some(*v);
            }
        }
    }
}

#[tokio::test]
async fn hello_view_single_instance_and_private_socket() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new("single");
    env.config("");
    let _d = Guard(env.daemon());
    let stream = wait_socket(&env.socket()).await;
    let mode = std::fs::metadata(env.socket())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "only the owner may connect");

    let mut c = Client::new(stream);
    let first = c.lines.next_line().await.unwrap().unwrap();
    assert!(
        matches!(decode::<Update>(&first), Ok(Update::Hello { .. })),
        "{first}"
    );
    c.until("a view", |_| true).await;
    // Without a desktop session there is no tray: that is a log line, not an error.
    let mut saw_tray_note = false;
    for _ in 0..5 {
        let l = c.lines.next_line().await.unwrap().unwrap();
        if l.contains("в трее недоступен") {
            saw_tray_note = true;
            break;
        }
    }
    assert!(saw_tray_note, "the no-tray case must be logged");

    // A second background process refuses to start and exits at once; the first keeps serving.
    let mut second = env.daemon();
    let status = tokio::task::spawn_blocking(move || second.wait().unwrap())
        .await
        .unwrap();
    assert!(status.success());
    c.send(Cmd::ToggleMode).await;
    c.until("mode TUN", |v| {
        v.mode == elf_gate::model::rule::TrafficMode::Tun
    })
    .await;
}

fn xray() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("XRAY_PATH") {
        return Some(PathBuf::from(p));
    }
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("bin/xray");
    p.is_file().then_some(p)
}

fn pgrep_count(pattern: &str) -> usize {
    let out = Command::new("pgrep")
        .args(["-fc", pattern])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

#[tokio::test]
async fn vpn_outlives_the_interface_and_dies_with_the_daemon() {
    let Some(xray) = xray() else {
        eprintln!("SKIPPED: no Xray binary");
        return;
    };
    let env = Env::new("outlive");
    let base = 31000 + (std::process::id() % 2000) as u16 * 2;
    let (socks, http) = (base, base + 1);
    // A local VLESS "server": the daemon only needs something that answers on TCP.
    let server_port = base + 4000;
    let srv_cfg = env.dir.join("server.json");
    std::fs::write(
        &srv_cfg,
        serde_json::json!({
            "inbounds": [{"listen":"127.0.0.1","port":server_port,"protocol":"vless",
                "settings":{"clients":[{"id":UUID}],"decryption":"none"},
                "streamSettings":{"network":"tcp","security":"none"}}],
            "outbounds":[{"protocol":"freedom"}]
        })
        .to_string(),
    )
    .unwrap();
    let _server = Guard(
        Command::new(&xray)
            .args(["run", "-c"])
            .arg(&srv_cfg)
            .env("XRAY_LOCATION_ASSET", xray.parent().unwrap())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    env.config(&format!(
        "[core]\nxray_path = \"{}\"\nsocks_port = {socks}\nhttp_port = {http}\n[proxy]\nset_system_proxy = false\n",
        xray.display()
    ));
    let mut daemon = env.daemon();
    let stream = wait_socket(&env.socket()).await;
    let mut c = Client::new(stream);
    c.until("a view", |_| true).await;
    c.send(Cmd::AddLink(format!(
        "vless://{UUID}@127.0.0.1:{server_port}?security=none&type=tcp#local"
    )))
    .await;
    let v = c.until("the server", |v| !v.groups.is_empty()).await;
    let id = v.groups[0].servers[0].id;
    assert!(
        v.groups[0].servers[0].link.is_empty(),
        "links never cross the link"
    );
    c.send(Cmd::Connect(id)).await;
    c.until("connected", |v| v.conn == Conn::Connected(id))
        .await;
    assert!(std::net::TcpStream::connect(("127.0.0.1", socks)).is_ok());

    // The interface goes away: the VPN stays.
    drop(c);
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", socks)).is_ok(),
        "core must survive"
    );

    // A new interface sees the live connection.
    let mut c2 = Client::new(UnixStream::connect(env.socket()).await.unwrap());
    c2.until("still connected", |v| v.conn == Conn::Connected(id))
        .await;

    // kill -9 on the daemon: the core must not be left behind.
    let before = pgrep_count(&format!(
        "xray run -c {}",
        env.dir.join("state/elf-gate/run/xray.json").display()
    ));
    assert!(before >= 1, "the core is running");
    daemon.kill().unwrap();
    daemon.wait().unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    while std::net::TcpStream::connect(("127.0.0.1", socks)).is_ok() {
        assert!(Instant::now() < end, "the core outlived a killed daemon");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
