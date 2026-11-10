use super::{fragment_name, ParseError};
use crate::model::server::{Ping, Security, Server, TlsParams, Transport, TransportParams};
use percent_encoding::percent_decode_str;
use std::collections::HashMap;
use std::net::IpAddr;
use url::Url;

/// Does Xray 26.x refuse unencrypted VLESS to this *IP address*? It only accepts private
/// ranges. Domains are deliberately not judged here: whether a name is acceptable is
/// decided by Xray itself (`xray::validate`), not by a table of suffixes.
/// The ranges were found with `xray run -test` (v26.11.9); an integration test re-checks them.
pub fn plain_vless_blocked_for_ip(address: &str) -> bool {
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => !(v4.is_loopback() || v4.is_private() || v4.is_link_local()),
        Ok(IpAddr::V6(v6)) => {
            let first = v6.segments()[0];
            !(v6.is_loopback() || first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80)
        }
        Err(_) => false,
    }
}

pub const PLAIN_VLESS_REASON: &str = "несовместим с текущим Xray: VLESS без шифрования \
(security=none, encryption=none) на публичный IP запрещён. Нужен TLS/Reality или encryption";

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
        && plain_vless_blocked_for_ip(&address)
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
        authority: get("authority"),
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
        fp_override: None,
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
    fn plain_vless_to_public_ip_is_marked_incompatible() {
        for host in ["8.8.8.8", "[2001:db8::1]", "100.64.0.1", "172.32.0.1"] {
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
    fn domains_are_left_to_xray_validation() {
        // No suffix table: the parser never judges names, `xray run -test` does.
        for host in [
            "example.com",
            "vps1",
            "box.lan",
            "de1.vpn.example.org",
            "тест",
        ] {
            let s = parse_link(&format!("vless://{UUID}@{host}:443?security=none#d")).unwrap();
            assert!(s.is_supported(), "{host}");
        }
    }

    #[test]
    fn plain_vless_to_private_ip_is_fine() {
        for host in [
            "10.0.0.5",
            "192.168.1.9",
            "172.16.3.3",
            "127.0.0.1",
            "[::1]",
            "[fd00::1]",
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
    fn ip_table() {
        for (addr, blocked) in [
            ("127.0.0.1", false),
            ("10.1.2.3", false),
            ("172.16.0.1", false),
            ("172.32.0.1", true),
            ("192.168.1.1", false),
            ("169.254.1.1", false),
            ("100.64.0.1", true),
            ("8.8.8.8", true),
            ("::1", false),
            ("fd00::1", false),
            ("fe80::1", false),
            ("2001:db8::1", true),
            // Not IP addresses: never judged here.
            ("example.com", false),
            ("localhost", false),
            ("", false),
        ] {
            assert_eq!(plain_vless_blocked_for_ip(addr), blocked, "{addr}");
        }
    }

    #[test]
    fn ws_and_grpc_are_deprecated_but_supported() {
        for (ty, extra) in [("ws", ""), ("grpc", "&serviceName=s")] {
            let s = parse_link(&format!(
                "vless://{UUID}@h.example.com:443?security=tls&type={ty}{extra}#t"
            ))
            .unwrap();
            assert!(s.is_supported());
            assert!(s.deprecated_transport().unwrap().contains(ty));
        }
        for ty in ["tcp", "xhttp"] {
            let s = parse_link(&format!(
                "vless://{UUID}@h.example.com:443?security=tls&type={ty}#t"
            ))
            .unwrap();
            assert!(s.deprecated_transport().is_none());
        }
        // Incompatible servers are not additionally tagged as deprecated.
        let bad = parse_link(&format!("vless://{UUID}@8.8.8.8:443?type=ws#t")).unwrap();
        assert!(!bad.is_supported() && bad.deprecated_transport().is_none());
    }

    #[test]
    fn grpc_authority_and_multi_mode() {
        let s = parse_link(&format!(
            "vless://{UUID}@g.example.com:443?security=tls&sni=g.example.com&type=grpc&serviceName=svc&authority=cdn.example.com&mode=multi#G"
        ))
        .unwrap();
        assert_eq!(s.transport, Transport::Grpc);
        assert_eq!(s.params.service_name, "svc");
        assert_eq!(s.params.authority, "cdn.example.com");
        assert_eq!(s.params.mode, "multi");
    }

    #[test]
    fn fingerprint_is_kept_exactly_as_in_the_link() {
        for fp in ["chrome", "firefox", "random", "weird-custom"] {
            let s = parse_link(&format!(
                "vless://{UUID}@h.example.com:443?security=reality&pbk=K&sni=x.org&fp={fp}#t"
            ))
            .unwrap();
            assert_eq!(s.tls.fingerprint, fp);
            assert_eq!(
                s.fp_override, None,
                "the parser never substitutes a fingerprint"
            );
            assert_eq!(s.effective_fingerprint(), fp);
        }
    }
}
