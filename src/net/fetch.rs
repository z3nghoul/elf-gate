//! Downloads a subscription.

use crate::model::subscription::SubscriptionInfo;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::time::Duration;

pub const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
pub const DEFAULT_USER_AGENT: &str = "v2rayN/7.0";
/// Subscriptions are lists of links: anything bigger than this is not one.
const MAX_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub struct Fetched {
    pub body: String,
    pub info: Option<SubscriptionInfo>,
    /// `profile-title` header, decoded.
    pub title: Option<String>,
}

/// `subscription-userinfo: upload=1; download=2; total=3; expire=1700000000`.
pub fn parse_userinfo(header: &str) -> Option<SubscriptionInfo> {
    let mut info = SubscriptionInfo::default();
    let mut any = false;
    for part in header.split(';') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let Ok(n) = value.trim().parse::<u64>() else {
            continue;
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "upload" => info.upload = n,
            "download" => info.download = n,
            "total" => info.total = n,
            // 0 means "never expires" for most providers.
            "expire" => info.expire = (n > 0).then_some(n as i64),
            _ => continue,
        }
        any = true;
    }
    any.then_some(info)
}

/// `profile-title` is either plain text or `base64:<text>`.
pub fn parse_title(header: &str) -> Option<String> {
    let h = header.trim();
    let text = match h.strip_prefix("base64:") {
        Some(b) => String::from_utf8(STANDARD.decode(b.trim()).ok()?).ok()?,
        None => h.to_string(),
    };
    let text = text.trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Direct request: the system proxy (which may be elf-gate's own) is never used, so the
/// subscription is fetched the same way in every mode. In TUN mode the routing rules send
/// elf-gate's own process outside the tunnel.
pub async fn fetch(url: &str, user_agent: &str) -> Result<Fetched, String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(FETCH_TIMEOUT)
        .user_agent(if user_agent.is_empty() {
            DEFAULT_USER_AGENT
        } else {
            user_agent
        })
        .build()
        .map_err(|e| format!("не удалось создать HTTP-клиент: {e}"))?;
    let resp = client.get(url).send().await.map_err(describe)?;
    if !resp.status().is_success() {
        return Err(format!("сервер подписки ответил {}", resp.status()));
    }
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let info = header("subscription-userinfo").and_then(|h| parse_userinfo(&h));
    let title = header("profile-title").and_then(|h| parse_title(&h));
    if resp.content_length().is_some_and(|n| n as usize > MAX_BODY) {
        return Err("ответ слишком большой для подписки".into());
    }
    let bytes = resp.bytes().await.map_err(describe)?;
    if bytes.len() > MAX_BODY {
        return Err("ответ слишком большой для подписки".into());
    }
    Ok(Fetched {
        body: String::from_utf8_lossy(&bytes).into_owned(),
        info,
        title,
    })
}

fn describe(e: reqwest::Error) -> String {
    if e.is_timeout() {
        "подписка не загрузилась за 15 с".into()
    } else if e.is_connect() {
        "нет соединения с сервером подписки (проверьте интернет)".into()
    } else {
        format!("не удалось загрузить подписку: {e}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn userinfo_header() {
        let i = parse_userinfo("upload=10; download=20; total=1000; expire=1893456000").unwrap();
        assert_eq!((i.upload, i.download, i.total), (10, 20, 1000));
        assert_eq!(i.expire, Some(1_893_456_000));
        assert_eq!(parse_userinfo("expire=0;total=5").unwrap().expire, None);
        assert!(parse_userinfo("garbage").is_none());
        assert_eq!(parse_userinfo("download=7").unwrap().used(), 7);
    }

    #[test]
    fn title_plain_and_base64() {
        assert_eq!(parse_title(" My VPN "), Some("My VPN".into()));
        let b = format!("base64:{}", STANDARD.encode("Мой VPN"));
        assert_eq!(parse_title(&b), Some("Мой VPN".into()));
        assert_eq!(parse_title("base64:!!!"), None);
        assert_eq!(parse_title(" "), None);
    }

    async fn serve_once(response: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let _ = s.write_all(response.as_bytes()).await;
            }
        });
        format!("http://127.0.0.1:{port}/sub")
    }

    #[tokio::test]
    async fn fetches_body_and_headers() {
        let url = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nsubscription-userinfo: download=5; total=9\r\nprofile-title: T\r\nConnection: close\r\n\r\nhello",
        )
        .await;
        let f = fetch(&url, "test-agent").await.unwrap();
        assert_eq!(f.body, "hello");
        assert_eq!(f.info.unwrap().total, 9);
        assert_eq!(f.title.as_deref(), Some("T"));
    }

    #[tokio::test]
    async fn http_errors_and_dead_hosts_are_messages() {
        let url =
            serve_once("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        assert!(fetch(&url, "").await.unwrap_err().contains("403"));
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = dead.local_addr().unwrap().port();
        drop(dead);
        let err = fetch(&format!("http://127.0.0.1:{port}/"), "")
            .await
            .unwrap_err();
        assert!(err.contains("нет соединения"), "{err}");
    }
}
