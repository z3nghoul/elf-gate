//! Is traffic really getting through the VPN? An HTTP request to a `generate_204` endpoint
//! through the local socks inbound, with a timeout. The config routes this one host through
//! the proxy outbound whatever the user's rules say, so the answer is about the VPN, not about
//! the direct path. Stage 6 reuses this for automatic failover.

use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Always routed through the proxy outbound by the generated config.
pub const HEALTH_HOST: &str = "connectivitycheck.gstatic.com";
pub const HEALTH_PATH: &str = "/generate_204";
pub const HEALTH_TIMEOUT: Duration = Duration::from_secs(8);

/// A name that is blocked for many users and is the usual victim of DNS leaking around the
/// tunnel.
pub const DNS_PROBE_HOST: &str = "youtube.com";

/// Does `DNS_PROBE_HOST` resolve through the system resolver (the path every program uses)?
/// Two tries: the first can race with the adapter's resolver settings.
pub async fn system_dns_resolves() -> bool {
    for attempt in 0..2 {
        let lookup = tokio::net::lookup_host((DNS_PROBE_HOST, 443));
        if let Ok(Ok(mut found)) = timeout(Duration::from_secs(5), lookup).await {
            if found.next().is_some() {
                return true;
            }
        }
        if attempt == 0 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    false
}

/// `Ok(latency)` if the endpoint answered 204 through the proxy.
pub async fn check(socks_port: u16, limit: Duration) -> Result<Duration, String> {
    check_host(socks_port, HEALTH_HOST, HEALTH_PATH, limit).await
}

/// Requests per latency series through the live tunnel. The first one is "cold" (the far side
/// is dialled, caches are empty) and is thrown away, the median of the others is shown.
pub const SERIES_REQUESTS: usize = 4;
/// The whole series, however slow the single requests are.
pub const SERIES_TIMEOUT: Duration = Duration::from_secs(20);

/// The median of a series without its first (cold) sample, and how many samples it is made of.
/// `None` when nothing is left after dropping the cold one.
pub fn median_without_cold(samples: &[Duration]) -> Option<(Duration, usize)> {
    let mut rest: Vec<Duration> = samples.iter().skip(1).copied().collect();
    if rest.is_empty() {
        return None;
    }
    rest.sort();
    let n = rest.len();
    let median = if n % 2 == 1 {
        rest[n / 2]
    } else {
        (rest[n / 2 - 1] + rest[n / 2]) / 2
    };
    Some((median, n))
}

/// Several requests through the already working tunnel (the running core's socks inbound, not a
/// temporary core): the median of all but the cold first one, and the number of samples used.
pub async fn latency_series(socks_port: u16, each: Duration) -> Option<(Duration, usize)> {
    let run = async {
        let mut samples = Vec::new();
        for _ in 0..SERIES_REQUESTS {
            if let Ok(d) = check(socks_port, each).await {
                samples.push(d);
            }
        }
        samples
    };
    let samples = timeout(SERIES_TIMEOUT, run).await.ok()?;
    median_without_cold(&samples)
}

pub async fn check_host(
    socks_port: u16,
    host: &str,
    path: &str,
    limit: Duration,
) -> Result<Duration, String> {
    // The latency is the request itself (the proxy connection and the far side's dial are
    // set up before the clock starts), so it does not jump with connection set-up.
    match timeout(limit, request(socks_port, host, path)).await {
        Ok(Ok(latency)) => Ok(latency),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(crate::t!("net.no_answer", secs = limit.as_secs())),
    }
}

async fn request(socks_port: u16, host: &str, path: &str) -> Result<Duration, String> {
    let io = |what: String| move |e: std::io::Error| format!("{what}: {e}");
    let mut s = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .map_err(io(crate::t!("net.proxy_down")))?;
    // SOCKS5: no authentication, CONNECT to a domain name (resolved on the far side).
    s.write_all(&[5, 1, 0])
        .await
        .map_err(io("socks".to_string()))?;
    let mut method = [0u8; 2];
    s.read_exact(&mut method)
        .await
        .map_err(io("socks".to_string()))?;
    if method != [5, 0] {
        return Err(crate::t!("net.proxy_refused"));
    }
    let name = host.as_bytes();
    let mut req = vec![5, 1, 0, 3, name.len() as u8];
    req.extend_from_slice(name);
    req.extend_from_slice(&80u16.to_be_bytes());
    s.write_all(&req).await.map_err(io("socks".to_string()))?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)
        .await
        .map_err(io(crate::t!("net.via_server")))?;
    if head[1] != 0 {
        return Err(crate::t!("net.server_refused", code = head[1]));
    }
    // Skip the bound address of the reply.
    let skip = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len)
                .await
                .map_err(io("socks".to_string()))?;
            len[0] as usize + 2
        }
        _ => return Err(crate::t!("net.bad_socks")),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest)
        .await
        .map_err(io("socks".to_string()))?;

    let get = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: elf-gate\r\n\r\n"
    );
    let started = Instant::now();
    s.write_all(get.as_bytes())
        .await
        .map_err(io(crate::t!("net.request")))?;
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).await.map_err(io(crate::t!("net.reply")))?;
    let latency = started.elapsed();
    let line = String::from_utf8_lossy(&buf[..n]);
    if line.starts_with("HTTP/1.1 204") || line.starts_with("HTTP/1.0 204") {
        Ok(latency)
    } else {
        let first = line.lines().next().unwrap_or("").trim();
        Err(crate::t!("net.unexpected", first = format!("{first:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_median_drops_the_cold_first_sample() {
        let ms = |v: &[u64]| {
            v.iter()
                .map(|m| Duration::from_millis(*m))
                .collect::<Vec<_>>()
        };
        // A slow first request must not pull the number up.
        assert_eq!(
            median_without_cold(&ms(&[900, 100, 110, 105])),
            Some((Duration::from_millis(105), 3))
        );
        // Even count: the middle pair is averaged; one outlier among the rest is ignored.
        assert_eq!(
            median_without_cold(&ms(&[500, 100, 900, 110, 120])),
            Some((Duration::from_millis(115), 4))
        );
        assert_eq!(median_without_cold(&ms(&[500])), None);
        assert_eq!(median_without_cold(&[]), None);
    }
    use tokio::net::TcpListener;

    /// A pocket SOCKS5 server that "reaches the internet" and answers with `status`.
    async fn fake_socks(status: &'static str, reply_code: u8) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let mut hello = [0u8; 3];
            s.read_exact(&mut hello).await.unwrap();
            s.write_all(&[5, 0]).await.unwrap();
            let mut head = [0u8; 5];
            s.read_exact(&mut head).await.unwrap();
            let mut rest = vec![0u8; head[4] as usize + 2];
            s.read_exact(&mut rest).await.unwrap();
            s.write_all(&[5, reply_code, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            if reply_code != 0 {
                return;
            }
            let mut req = [0u8; 256];
            let _ = s.read(&mut req).await;
            let _ = s.write_all(status.as_bytes()).await;
        });
        port
    }

    #[tokio::test]
    async fn answer_204_is_healthy() {
        let port = fake_socks("HTTP/1.1 204 No Content\r\n\r\n", 0).await;
        let latency = check(port, Duration::from_secs(3)).await.unwrap();
        assert!(latency < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn captive_portal_style_answers_are_failures() {
        let port = fake_socks(
            "HTTP/1.1 302 Found\r\nLocation: http://block.example/\r\n\r\n",
            0,
        )
        .await;
        let err = check(port, Duration::from_secs(3)).await.unwrap_err();
        assert!(err.contains("неожиданный ответ"), "{err}");
    }

    #[tokio::test]
    async fn socks_failure_code_is_reported() {
        let port = fake_socks("", 4).await;
        let err = check(port, Duration::from_secs(3)).await.unwrap_err();
        assert!(err.contains("код socks 4"), "{err}");
    }

    #[tokio::test]
    async fn silent_proxy_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let err = check(port, Duration::from_millis(400)).await.unwrap_err();
        assert!(err.contains("нет ответа"), "{err}");
    }

    #[tokio::test]
    async fn dead_local_proxy_is_reported() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        // Windows retries a refused connection for a couple of seconds, so allow for that.
        let err = check(port, Duration::from_secs(10)).await.unwrap_err();
        assert!(err.contains("локальный прокси недоступен"), "{err}");
    }
}
