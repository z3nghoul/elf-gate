use super::{fragment_name, ParseError};
use crate::model::server::{Ping, Security, Server, TlsParams, Transport, TransportParams};
use percent_encoding::percent_decode_str;
use std::collections::HashMap;
use url::Url;

/// `vless://uuid@host:port?params#name`
pub fn parse(link: &str) -> Result<Server, ParseError> {
    let url = Url::parse(link).map_err(|e| ParseError::InvalidUrl(e.to_string()))?;

    let uuid = percent_decode_str(url.username())
        .decode_utf8_lossy()
        .to_string();
    if uuid.is_empty() {
        return Err(ParseError::MissingUuid);
    }
    let host = url.host_str().unwrap_or_default();
    // IPv6 comes in brackets; Xray wants the bare address.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let address = percent_decode_str(host).decode_utf8_lossy().to_string();
    if address.is_empty() {
        return Err(ParseError::MissingHost);
    }
    let port = url.port().ok_or(ParseError::MissingPort)?;

    let q: HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let get = |key: &str| q.get(key).cloned().unwrap_or_default();

    let mut unsupported = None;
    let security = match get("security").to_ascii_lowercase().as_str() {
        "" | "none" => Security::None,
        "tls" => Security::Tls,
        "reality" => Security::Reality,
        other => {
            unsupported = Some(format!("security={other} не поддерживается"));
            Security::None
        }
    };
    let transport = match get("type").to_ascii_lowercase().as_str() {
        "" | "tcp" => Transport::Tcp,
        "xhttp" | "splithttp" => Transport::Xhttp,
        "grpc" => Transport::Grpc,
        "ws" => Transport::Ws,
        other => {
            unsupported.get_or_insert(format!("транспорт type={other} не поддерживается"));
            Transport::Tcp
        }
    };

    let flag = |v: String| matches!(v.to_ascii_lowercase().as_str(), "1" | "true");
    let tls = TlsParams {
        sni: get("sni"),
        fingerprint: get("fp"),
        alpn: get("alpn")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        public_key: get("pbk"),
        short_id: get("sid"),
        spider_x: get("spx"),
        allow_insecure: flag(get("allowInsecure")) || flag(get("insecure")),
    };
    let params = TransportParams {
        path: get("path"),
        host: get("host"),
        mode: get("mode"),
        service_name: get("serviceName"),
    };

    let name = fragment_name(link).unwrap_or_else(|| {
        if address.contains(':') {
            format!("[{address}]:{port}")
        } else {
            format!("{address}:{port}")
        }
    });

    Ok(Server {
        id: 0,
        name,
        address,
        port,
        uuid,
        flow: get("flow"),
        security,
        transport,
        tls,
        params,
        link: link.to_string(),
        unsupported,
        ping: Ping::Unknown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_link;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn reality_tcp_vision() {
        let s = parse_link(&format!(
            "vless://{UUID}@de.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY123&sid=ab12&spx=%2F&type=tcp&headerType=none#DE-1"
        ))
        .unwrap();
        assert_eq!(s.name, "DE-1");
        assert_eq!(s.uuid, UUID);
        assert_eq!(s.address, "de.example.com");
        assert_eq!(s.port, 443);
        assert_eq!(s.flow, "xtls-rprx-vision");
        assert_eq!(s.security, Security::Reality);
        assert_eq!(s.transport, Transport::Tcp);
        assert_eq!(s.tls.sni, "www.microsoft.com");
        assert_eq!(s.tls.fingerprint, "chrome");
        assert_eq!(s.tls.public_key, "PUBKEY123");
        assert_eq!(s.tls.short_id, "ab12");
        assert_eq!(s.tls.spider_x, "/");
        assert!(s.is_supported());
    }

    #[test]
    fn reality_xhttp() {
        let s = parse_link(&format!(
            "vless://{UUID}@nl.example.com:443?security=reality&sni=example.org&fp=firefox&pbk=K&sid=1&type=xhttp&path=%2Fxh&host=cdn.example.org&mode=packet-up#NL-2"
        ))
        .unwrap();
        assert_eq!(s.transport, Transport::Xhttp);
        assert_eq!(s.params.path, "/xh");
        assert_eq!(s.params.host, "cdn.example.org");
        assert_eq!(s.params.mode, "packet-up");
    }

    #[test]
    fn tls_ws() {
        let s = parse_link(&format!(
            "vless://{UUID}@fi.example.com:8443?security=tls&sni=fi.example.com&alpn=h2%2Chttp%2F1.1&fp=chrome&type=ws&path=%2Fws%3Fed%3D2048&host=fi.example.com#FI-1"
        ))
        .unwrap();
        assert_eq!(s.security, Security::Tls);
        assert_eq!(s.transport, Transport::Ws);
        assert_eq!(s.tls.alpn, vec!["h2", "http/1.1"]);
        assert_eq!(s.params.path, "/ws?ed=2048");
        assert_eq!(s.port, 8443);
    }

    #[test]
    fn tls_grpc() {
        let s = parse_link(&format!(
            "vless://{UUID}@g.example.com:443?security=tls&sni=g.example.com&type=grpc&serviceName=my%20svc&mode=gun#GRPC"
        ))
        .unwrap();
        assert_eq!(s.transport, Transport::Grpc);
        assert_eq!(s.params.service_name, "my svc");
    }

    #[test]
    fn cyrillic_and_emoji_name() {
        let s = parse_link(&format!(
            "vless://{UUID}@h.example.com:443?type=tcp#%F0%9F%87%A9%F0%9F%87%AA%20%D0%93%D0%B5%D1%80%D0%BC%D0%B0%D0%BD%D0%B8%D1%8F"
        ))
        .unwrap();
        assert_eq!(s.name, "🇩🇪 Германия");
    }

    #[test]
    fn raw_unicode_name_in_fragment() {
        let s = parse_link(&format!("vless://{UUID}@h.example.com:443#Финляндия 🚀")).unwrap();
        assert_eq!(s.name, "Финляндия 🚀");
    }

    #[test]
    fn ipv6_address_in_brackets() {
        let s = parse_link(&format!("vless://{UUID}@[2001:db8::1]:443?type=tcp#v6")).unwrap();
        assert_eq!(s.address, "2001:db8::1");
        assert_eq!(s.host_port(), "[2001:db8::1]:443");
    }

    #[test]
    fn ipv4_address() {
        let s = parse_link(&format!("vless://{UUID}@203.0.113.7:2053#ip")).unwrap();
        assert_eq!(s.address, "203.0.113.7");
        assert_eq!(s.port, 2053);
    }

    #[test]
    fn optional_params_missing() {
        let s = parse_link(&format!("vless://{UUID}@h.example.com:443")).unwrap();
        assert_eq!(s.security, Security::None);
        assert_eq!(s.transport, Transport::Tcp);
        assert_eq!(s.flow, "");
        assert!(s.tls.alpn.is_empty());
        assert!(!s.tls.allow_insecure);
        // No fragment: the name falls back to host:port.
        assert_eq!(s.name, "h.example.com:443");
    }

    #[test]
    fn allow_insecure_flag() {
        let s = parse_link(&format!(
            "vless://{UUID}@h.example.com:443?security=tls&allowInsecure=1"
        ))
        .unwrap();
        assert!(s.tls.allow_insecure);
    }

    #[test]
    fn whitespace_around_link_is_trimmed() {
        let s = parse_link(&format!("  vless://{UUID}@h.example.com:443#x \n")).unwrap();
        assert_eq!(s.name, "x");
        assert!(!s.link.contains('\n'));
    }

    #[test]
    fn unsupported_transport_is_marked_not_dropped() {
        let s = parse_link(&format!("vless://{UUID}@h.example.com:443?type=kcp#K")).unwrap();
        assert!(!s.is_supported());
        assert_eq!(s.name, "K");
    }

    #[test]
    fn broken_links_are_errors() {
        assert_eq!(
            parse_link("vless://h.example.com:443"),
            Err(ParseError::MissingUuid)
        );
        assert_eq!(
            parse_link(&format!("vless://{UUID}@h.example.com")),
            Err(ParseError::MissingPort)
        );
        assert!(matches!(
            parse_link(&format!("vless://{UUID}@h.example.com:notaport")),
            Err(ParseError::InvalidUrl(_))
        ));
        assert!(matches!(
            parse_link(&format!("vless://{UUID}@:443")),
            Err(ParseError::MissingHost | ParseError::InvalidUrl(_))
        ));
    }
}
