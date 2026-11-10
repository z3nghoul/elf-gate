use super::{fragment_name, ParseError};
use crate::model::server::{Ping, Security, Server, TlsParams, Transport, TransportParams};
use percent_encoding::percent_decode_str;
use std::collections::HashMap;
use std::net::IpAddr;
use url::Url;

/// Suffixes of non-IP server addresses that Xray 26.x accepts for unencrypted VLESS.
/// Found empirically with `xray run -test` (v26.11.9); the integration tests re-check
/// this table against the installed Xray.
const PRIVATE_DOMAIN_SUFFIXES: &[&str] = &[
    "local",
    "lan",
    "internal",
    "test",
    "localhost",
    "localdomain",
    "home.arpa",
    "example",
    "invalid",
];

/// Does Xray allow VLESS without TLS/Reality and without `encryption` to this address?
/// It only does for private IPs and private-looking names.
pub fn xray_allows_plain_vless(address: &str) -> bool {
    if let Ok(ip) = address.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            IpAddr::V6(v6) => {
                let first = v6.segments()[0];
                v6.is_loopback() || first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
            }
        };
    }
    let name = address.to_ascii_lowercase();
    if name.is_empty() || !name.is_ascii() {
        return false;
    }
    if !name.contains('.') {
        return true; // single-label name such as `vps1`
    }
    PRIVATE_DOMAIN_SUFFIXES
        .iter()
        .any(|suffix| name == *suffix || name.ends_with(&format!(".{suffix}")))
}

pub const PLAIN_VLESS_REASON: &str = "несовместим с текущим Xray: VLESS без шифрования \
(security=none, encryption=none) на публичный адрес запрещён. Нужен TLS/Reality или encryption";

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

    let encryption = match get("encryption") {
        e if e.trim().is_empty() => "none".to_string(),
        e => e,
    };
    if security == Security::None
        && encryption.eq_ignore_ascii_case("none")
        && !xray_allows_plain_vless(&address)
    {
        unsupported.get_or_insert_with(|| PLAIN_VLESS_REASON.to_string());
    }

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
        encryption,
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
        let s = parse_link(&format!(
            "vless://{UUID}@h.example.com:443?security=tls#Финляндия 🚀"
        ))
        .unwrap();
        assert_eq!(s.name, "Финляндия 🚀");
    }

    #[test]
    fn ipv6_address_in_brackets() {
        let s = parse_link(&format!("vless://{UUID}@[fd00::1]:443?type=tcp#v6")).unwrap();
        assert_eq!(s.address, "fd00::1");
        assert_eq!(s.host_port(), "[fd00::1]:443");
    }

    #[test]
    fn ipv4_address() {
        let s = parse_link(&format!("vless://{UUID}@10.0.0.7:2053#ip")).unwrap();
        assert_eq!(s.address, "10.0.0.7");
        assert_eq!(s.port, 2053);
    }

    #[test]
    fn optional_params_missing() {
        let s = parse_link(&format!("vless://{UUID}@h.example.com:443?security=tls")).unwrap();
        assert_eq!(s.security, Security::Tls);
        assert_eq!(s.encryption, "none");
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
        let s = parse_link(&format!(
            "  vless://{UUID}@h.example.com:443?security=tls#x \n"
        ))
        .unwrap();
        assert_eq!(s.name, "x");
        assert!(!s.link.contains('\n'));
    }

    #[test]
    fn unsupported_transport_is_marked_not_dropped() {
        let s = parse_link(&format!(
            "vless://{UUID}@h.example.com:443?security=tls&type=kcp#K"
        ))
        .unwrap();
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

    const PQ_ENC: &str =
        "mlkem768x25519plus.native.0rtt.45M6KAE8QF6VlzscrkIrjshB78IYPvGemYDCFrzFi14";

    #[test]
    fn encryption_is_passed_through_unchanged() {
        let s = parse_link(&format!(
            "vless://{UUID}@8.8.8.8:443?security=none&encryption={PQ_ENC}#pq"
        ))
        .unwrap();
        assert_eq!(s.encryption, PQ_ENC);
        // A real encryption makes plain transport to a public address legitimate.
        assert!(s.is_supported());
    }

    #[test]
    fn plain_vless_to_public_address_is_marked_incompatible() {
        for host in [
            "8.8.8.8",
            "example.com",
            "de1.vpn.example.org",
            "[2001:db8::1]",
            "100.64.0.1",
        ] {
            let s = parse_link(&format!(
                "vless://{UUID}@{host}:443?security=none&encryption=none#p"
            ))
            .unwrap();
            let reason = s
                .unsupported
                .unwrap_or_else(|| panic!("{host} must be incompatible"));
            assert!(reason.contains("Xray"), "{reason}");
        }
        // Missing params default to security=none, encryption=none.
        assert!(!parse_link(&format!("vless://{UUID}@8.8.8.8:443#p"))
            .unwrap()
            .is_supported());
    }

    #[test]
    fn plain_vless_to_private_address_is_fine() {
        for host in [
            "10.0.0.5",
            "192.168.1.9",
            "172.16.3.3",
            "127.0.0.1",
            "[::1]",
            "[fd00::1]",
            "vps1",
            "box.lan",
            "x.home.arpa",
        ] {
            let s = parse_link(&format!("vless://{UUID}@{host}:443?security=none#p")).unwrap();
            assert!(s.is_supported(), "{host}");
        }
    }

    #[test]
    fn tls_and_reality_to_public_address_are_fine() {
        for q in ["security=tls", "security=reality&pbk=K&sni=x.org"] {
            let s = parse_link(&format!("vless://{UUID}@8.8.8.8:443?{q}#p")).unwrap();
            assert!(s.is_supported(), "{q}");
        }
    }

    #[test]
    fn address_table() {
        for (addr, ok) in [
            ("127.0.0.1", true),
            ("10.1.2.3", true),
            ("172.16.0.1", true),
            ("172.32.0.1", false),
            ("192.168.1.1", true),
            ("169.254.1.1", true),
            ("100.64.0.1", false),
            ("8.8.8.8", false),
            ("::1", true),
            ("fd00::1", true),
            ("fe80::1", true),
            ("2001:db8::1", false),
            ("example.com", false),
            ("localhost", true),
            ("myserver", true),
            ("foo.local", true),
            ("foo.example", true),
            ("foo.dev", false),
            ("foo.corp", false),
            ("", false),
            ("тест", false),
        ] {
            assert_eq!(xray_allows_plain_vless(addr), ok, "{addr}");
        }
    }
}
