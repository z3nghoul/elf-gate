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

/// `Ok(latency)` if the endpoint answered 204 through the proxy.
pub async fn check(socks_port: u16, limit: Duration) -> Result<Duration, String> {
    check_host(socks_port, HEALTH_HOST, HEALTH_PATH, limit).await
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
        Err(_) => Err(format!("нет ответа за {} с", limit.as_secs())),
    }
}

async fn request(socks_port: u16, host: &str, path: &str) -> Result<Duration, String> {
    let io = |what: &'static str| move |e: std::io::Error| format!("{what}: {e}");
    let mut s = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .map_err(io("локальный прокси недоступен"))?;
    // SOCKS5: no authentication, CONNECT to a domain name (resolved on the far side).
    s.write_all(&[5, 1, 0]).await.map_err(io("socks"))?;
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await.map_err(io("socks"))?;
    if method != [5, 0] {
        return Err("локальный прокси отказал в подключении".into());
    }
    let name = host.as_bytes();
    let mut req = vec![5, 1, 0, 3, name.len() as u8];
    req.extend_from_slice(name);
    req.extend_from_slice(&80u16.to_be_bytes());
    s.write_all(&req).await.map_err(io("socks"))?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)
        .await
        .map_err(io("соединение через сервер"))?;
    if head[1] != 0 {
        return Err(format!(
            "сервер не смог открыть соединение (код socks {})",
            head[1]
        ));
    }
    // Skip the bound address of the reply.
    let skip = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await.map_err(io("socks"))?;
            len[0] as usize + 2
        }
        _ => return Err("непонятный ответ socks".into()),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest).await.map_err(io("socks"))?;

    let get = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: elf-gate\r\n\r\n"
    );
    let started = Instant::now();
    s.write_all(get.as_bytes()).await.map_err(io("запрос"))?;
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).await.map_err(io("ответ"))?;
    let latency = started.elapsed();
    let line = String::from_utf8_lossy(&buf[..n]);
    if line.starts_with("HTTP/1.1 204") || line.starts_with("HTTP/1.0 204") {
        Ok(latency)
    } else {
        let first = line.lines().next().unwrap_or("").trim();
        Err(format!(
            "неожиданный ответ: {first:?} (перехватчик провайдера или сбой сервера)"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
