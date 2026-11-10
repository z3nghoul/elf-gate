//! Server latency: a plain TCP connect, or a real request through a throw-away Xray.

use crate::model::server::{Ping, Server};
use crate::storage::{CoreConfig, PingConfig};
use crate::xray::config::{self, Plan};
use crate::xray::process::{Core, StartOptions};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};

/// TCP probes in flight at once.
pub const TCP_PARALLEL: usize = 16;
/// Temporary cores in flight at once (URL ping and fingerprint search share the limit).
pub const CORE_PARALLEL: usize = 4;

static TCP_PERMITS: Semaphore = Semaphore::const_new(TCP_PARALLEL);
static CORE_PERMITS: Semaphore = Semaphore::const_new(CORE_PARALLEL);
static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Fingerprints tried in this order by the automatic search. `firefox` comes first: it is the
/// one that works where a provider's DPI breaks Chrome's large post-quantum ClientHello.
pub const FP_SEARCH_ORDER: [&str; 7] =
    ["firefox", "chrome", "safari", "ios", "edge", "random", "qq"];

/// Measured attempts per ping; the median is shown (one slow outlier does not jump the value).
pub const SAMPLES: usize = 3;

/// The median of the samples (the mean of the two middle ones for an even count).
pub fn median(mut samples: Vec<Duration>) -> Option<Duration> {
    if samples.is_empty() {
        return None;
    }
    samples.sort();
    let n = samples.len();
    Some(if n % 2 == 1 {
        samples[n / 2]
    } else {
        (samples[n / 2 - 1] + samples[n / 2]) / 2
    })
}

fn millis(d: Duration) -> u32 {
    d.as_millis().min(u128::from(u32::MAX)) as u32
}

async fn connect_once(
    host: &str,
    port: u16,
    limit: Duration,
    interface: Option<&str>,
) -> Result<Duration, Ping> {
    let started = Instant::now();
    let connect = async {
        match interface {
            None => TcpStream::connect((host, port)).await,
            Some(iface) => {
                let addr = tokio::net::lookup_host((host, port))
                    .await?
                    .next()
                    .ok_or_else(|| std::io::Error::other("no address"))?;
                crate::platform::connect_via(addr, iface).await
            }
        }
    };
    match tokio::time::timeout(limit, connect).await {
        Ok(Ok(_)) => Ok(started.elapsed()),
        // Cannot bind to the interface: say "unknown", never a number that is not a measurement.
        Ok(Err(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::Unsupported | std::io::ErrorKind::PermissionDenied
            ) && interface.is_some() =>
        {
            Err(Ping::Unknown)
        }
        Ok(Err(_)) => Err(Ping::Error),
        Err(_) => Err(Ping::Timeout),
    }
}

/// Time to open a TCP connection to `host:port`: one warm-up connect (name lookup, ARP and
/// the first packets are slow and say nothing about the path) that is thrown away, then
/// `SAMPLES` measured ones; the median is the result.
pub async fn tcp_ping(host: &str, port: u16, limit: Duration) -> Ping {
    tcp_ping_via(host, port, limit, None).await
}

/// The same through one interface only. While the TUN is up a plain connect enters the tunnel,
/// whose stack answers the handshake itself within a couple of milliseconds: that says nothing
/// about the server. Bound to the physical interface the packets go around the tunnel.
pub async fn tcp_ping_via(host: &str, port: u16, limit: Duration, interface: Option<&str>) -> Ping {
    let _permit = TCP_PERMITS.acquire().await.ok();
    let warmup = connect_once(host, port, limit, interface).await;
    let mut samples = Vec::new();
    let mut failure = warmup.err();
    for i in 0..SAMPLES {
        if i > 0 {
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
        match connect_once(host, port, limit, interface).await {
            Ok(d) => samples.push(d),
            Err(f) => failure = Some(f),
        }
    }
    match median(samples) {
        Some(d) => Ping::Ms(millis(d)),
        None => failure.unwrap_or(Ping::Error),
    }
}

/// Two distinct free loopback ports (socks, http) for a temporary core.
fn free_ports() -> Option<(u16, u16)> {
    let a = TcpListener::bind(("127.0.0.1", 0)).ok()?;
    let b = TcpListener::bind(("127.0.0.1", 0)).ok()?;
    Some((a.local_addr().ok()?.port(), b.local_addr().ok()?.port()))
}

/// A request to `url` through a temporary core that uses `server` (with its current
/// settings), measured end to end.
pub async fn url_probe(
    binary: &Path,
    core: &CoreConfig,
    server: &Server,
    url: &str,
    limit: Duration,
    run_dir: &Path,
) -> Result<Duration, String> {
    let _permit = CORE_PERMITS.acquire().await.ok();
    let (socks, http) = free_ports().ok_or("нет свободных портов")?;
    let probe_core = CoreConfig {
        socks_port: socks,
        http_port: http,
        log_level: "none".into(),
        api_port: 0,
        ..core.clone()
    };
    let cfg = config::build_with(server, &probe_core, &Plan::proxy_default())
        .map_err(|e| e.to_string())?;
    let name = format!(
        "probe-{}-{}.json",
        std::process::id(),
        PROBE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let (log_tx, _log_rx) = mpsc::unbounded_channel();
    let opts = StartOptions {
        binary: Some(binary.to_path_buf()),
        config_name: Some(name.clone()),
        ..StartOptions::default()
    };
    let started = Core::start_with(&probe_core, &cfg, run_dir, log_tx, &opts).await;
    let _ = std::fs::remove_file(run_dir.join(&name));
    let core = started.map_err(|e| e.to_string())?;
    let result = request_through(socks, url, limit).await;
    core.stop().await;
    result
}

async fn request_through(socks_port: u16, url: &str, limit: Duration) -> Result<Duration, String> {
    let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{socks_port}"))
        .map_err(|e| e.to_string())?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(limit)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("elf-gate")
        .build()
        .map_err(|e| e.to_string())?;
    // One request that is not timed opens the connection through the tunnel (the way to the
    // server, its handshake, the target's TLS). The timed ones reuse it, so they measure the
    // request through the tunnel and not the set-up.
    let get = || async {
        let started = Instant::now();
        let resp = client.get(url).send().await.map_err(|e| {
            if e.is_timeout() {
                "timeout".to_string()
            } else {
                e.to_string()
            }
        })?;
        if resp.status().is_success() {
            Ok(started.elapsed())
        } else {
            Err(format!("ответ {}", resp.status()))
        }
    };
    get().await?;
    let mut samples = Vec::new();
    for _ in 0..SAMPLES {
        samples.push(get().await?);
    }
    median(samples).ok_or_else(|| "нет замеров".to_string())
}

/// Maps a probe outcome to the label shown in the server list.
pub fn ping_from_probe(result: &Result<Duration, String>) -> Ping {
    match result {
        Ok(d) => Ping::Ms(d.as_millis().min(u128::from(u32::MAX)) as u32),
        Err(e) if e == "timeout" => Ping::Timeout,
        Err(_) => Ping::Error,
    }
}

/// The URL ping of one server. The second value says: "the URL failed although the server
/// answers over TCP" (the situation where another fingerprint may help).
pub async fn url_ping(
    binary: &Path,
    core: &CoreConfig,
    server: &Server,
    ping: &PingConfig,
    run_dir: &Path,
) -> (Ping, bool) {
    let limit = Duration::from_millis(ping.timeout_ms.max(500));
    let result = url_probe(binary, core, server, &ping.url, limit, run_dir).await;
    let label = ping_from_probe(&result);
    let tcp_ok = if result.is_err() {
        matches!(
            tcp_ping(&server.address, server.port, limit).await,
            Ping::Ms(_)
        )
    } else {
        false
    };
    (label, tcp_ok)
}

/// Tries every fingerprint in `FP_SEARCH_ORDER` (up to four at the same time) and returns
/// the first one in that order that reaches the URL.
pub async fn search_fingerprint(
    binary: &Path,
    core: &CoreConfig,
    server: &Server,
    ping: &PingConfig,
    run_dir: &Path,
) -> Option<String> {
    let limit = Duration::from_millis(ping.timeout_ms.max(500));
    let mut tasks = tokio::task::JoinSet::new();
    for (rank, fp) in FP_SEARCH_ORDER.iter().enumerate() {
        let mut candidate = server.clone();
        candidate.fp_override = Some((*fp).to_string());
        let (binary, core, url, run_dir) = (
            binary.to_path_buf(),
            core.clone(),
            ping.url.clone(),
            run_dir.to_path_buf(),
        );
        tasks.spawn(async move {
            let ok = url_probe(&binary, &core, &candidate, &url, limit, &run_dir)
                .await
                .is_ok();
            (rank, ok)
        });
    }
    let mut best: Option<usize> = None;
    while let Some(Ok((rank, ok))) = tasks.join_next().await {
        if ok && best.is_none_or(|b| rank < b) {
            best = Some(rank);
        }
    }
    best.map(|r| FP_SEARCH_ORDER[r].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener as TokioListener;

    #[tokio::test]
    async fn tcp_ping_measures_open_ports_and_reports_closed_ones() {
        let l = TokioListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = l.accept().await;
            }
        });
        let ok = tcp_ping("127.0.0.1", port, Duration::from_secs(2)).await;
        assert!(matches!(ok, Ping::Ms(_)), "{ok:?}");
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        // Windows retries a refused loopback connect for about two seconds, so "closed" can
        // surface as a timeout there; either way it is not a measurement.
        let bad = tcp_ping("127.0.0.1", closed, Duration::from_secs(1)).await;
        assert!(matches!(bad, Ping::Error | Ping::Timeout), "{bad:?}");
    }

    #[test]
    fn the_median_ignores_one_outlier() {
        let ms = |v: &[u64]| median(v.iter().map(|m| Duration::from_millis(*m)).collect());
        assert_eq!(ms(&[40, 200, 41]), Some(Duration::from_millis(41)));
        assert_eq!(ms(&[40, 60]), Some(Duration::from_millis(50)));
        assert_eq!(ms(&[7]), Some(Duration::from_millis(7)));
        assert_eq!(ms(&[]), None);
    }

    #[test]
    fn probe_outcomes_map_to_labels() {
        assert_eq!(
            ping_from_probe(&Ok(Duration::from_millis(42))),
            Ping::Ms(42)
        );
        assert_eq!(ping_from_probe(&Err("timeout".into())), Ping::Timeout);
        assert_eq!(ping_from_probe(&Err("boom".into())), Ping::Error);
    }

    #[test]
    fn search_order_starts_with_firefox_and_has_no_duplicates() {
        assert_eq!(FP_SEARCH_ORDER[0], "firefox");
        let mut v = FP_SEARCH_ORDER.to_vec();
        v.sort();
        v.dedup();
        assert_eq!(v.len(), FP_SEARCH_ORDER.len());
    }
}
