use super::*;
use crate::parser::parse_link;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PBK: &str = "4GObrWHDR0TyD84iQ06z24v4YBxQ69vxeG1MCqOyFlI";

fn full(s: &str) -> String {
    text(s, Mode::Full)
}

#[test]
fn every_kind_of_link_is_replaced_whole() {
    for link in [
        format!("vless://{UUID}@de.example.com:443?security=reality&pbk={PBK}&sid=ab12cd34&sni=www.microsoft.com#DE-1"),
        "vmess://eyJhZGQiOiIxLjIuMy40In0=".to_string(),
        "trojan://password@trojan.example.net:443#T".to_string(),
        "ss://YWVzLTI1Ni1nY206cGFzcw@5.6.7.8:8388#S".to_string(),
        "hysteria2://pw@hy.example.org:443/?sni=x.org#H".to_string(),
        "https://panel.example.com/sub/SECRETTOKEN123456?x=1".to_string(),
    ] {
        for mode in [Mode::Secrets, Mode::Full] {
            let out = text(&format!("не удалось добавить {link} из буфера"), mode);
            assert!(out.contains("://***"), "{out}");
            for secret in [UUID, PBK, "SECRETTOKEN", "example", "5.6.7.8", "password", "eyJh", "ab12cd34"] {
                assert!(!out.contains(secret), "{secret} left in {out}");
            }
            assert!(out.starts_with("не удалось добавить ") && out.ends_with(" из буфера"), "{out}");
        }
    }
    assert_eq!(url("https://panel.example.com/sub/TOKEN"), "https://***");
    assert_eq!(url("garbage"), "***");
}

#[test]
fn core_log_lines_lose_addresses_and_names_but_keep_their_shape() {
    let line = "from tcp:198.18.0.1:39044 accepted tcp:212.147.241.154:443 [tun-in >> proxy]";
    assert_eq!(
        full(line),
        "from tcp:*.*.*.*:39044 accepted tcp:*.*.*.*:443 [tun-in >> proxy]"
    );
    assert_eq!(
        full("from udp:192.168.3.230:41977 accepted udp:160.79.104.10:443 [tun-in >> proxy]"),
        "from udp:*.*.*.*:41977 accepted udp:*.*.*.*:443 [tun-in >> proxy]"
    );
    assert_eq!(
        full("from tcp:127.0.0.1:58460 accepted tcp:connectivitycheck.gstatic.com:80 [socks-in -> proxy]"),
        "from tcp:*.*.*.*:58460 accepted tcp:***.com:80 [socks-in -> proxy]"
    );
    let err = full("[Error] dial tcp 203.0.113.9:443: connect: connection refused > failed to find 2001:db8::1");
    assert!(
        !err.contains("203.0.113.9") && !err.contains("2001:db8"),
        "{err}"
    );
    assert!(
        err.contains("[Error]") && err.contains(":443:") && err.contains("connection refused"),
        "{err}"
    );
    assert_eq!(
        full("proxy/vless/outbound: failed to dial vpn.example.com:8443 > EOF"),
        "proxy/vless/outbound: failed to dial ***.com:8443 > EOF"
    );
    assert_eq!(
        full("from [2001:db8::5]:5555 accepted"),
        "from [*:*:*:*]:5555 accepted"
    );
    assert_eq!(
        full("rule full:example.org -> direct"),
        "rule full:***.org -> direct"
    );
    // A host with a path (no scheme): both halves are looked at.
    assert!(
        !full("GET panel.example.com/sub/aGVsbG8gd29ybGQgdGhpcyBpcyBsb25n12345").contains("panel")
    );
}

#[test]
fn ids_and_keys_go_in_both_modes_and_ordinary_text_stays() {
    for mode in [Mode::Secrets, Mode::Full] {
        let out = text(&format!("user {UUID} pbk {PBK}"), mode);
        assert_eq!(out, "user *** pbk ***", "{mode:?}");
    }
    // A short id only in full mode (it is common in hashes); a long hex id in both.
    assert_eq!(full("sid ab12cd34"), "sid ***");
    assert_eq!(text("sid ab12cd34", Mode::Secrets), "sid ab12cd34");
    assert_eq!(text("hash 0123456789abcdef0123", Mode::Secrets), "hash ***");
    // Nothing else is touched.
    for s in [
        "started core for FI-1 (TUN)",
        "Xray 26.11.9 (Xray, Penetrates Everything.)",
        "xray: /usr/local/lib/elf-gate/xray, ассеты: /usr/local/lib/elf-gate (geoip.dat: есть, geosite.dat: НЕТ)",
        "2026/11/10 06:17:21.698994 [Info] app/observatory: checking proxy-primary",
        "config.toml elf-gated.log state.json check-cache.json",
        "подписка «EtherVPN» обновлена: 12 серверов",
        "порт 10808 (socks) уже занят",
        "deadbeef decade",
    ] {
        assert_eq!(full(s), s);
    }
}

#[test]
fn the_helpers_use_one_style() {
    assert_eq!(host("212.147.241.154"), IPV4_MASK);
    assert_eq!(host("2001:db8::1"), IPV6_MASK);
    assert_eq!(host("vpn.example.co.uk"), "***.uk");
    assert_eq!(host("localhost"), "***");
    assert_eq!(host(""), "");
    assert_eq!(hwid("0123456789abcdef"), "****************");
    assert_eq!(opaque("/secret/path"), "***");
    assert_eq!(opaque(""), "");
}

#[test]
fn a_server_copy_for_the_screen_has_no_secret_left() {
    let link = format!(
        "vless://{UUID}@de.example.com:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk={PBK}&sid=ab12cd34&spx=%2Fsecret&type=grpc&serviceName=svcname&host=cdn.example.org&authority=auth.example.org#DE-1"
    );
    let s = parse_link(&link).unwrap();
    let r = server(&s);
    let json = serde_json::to_string(&r).unwrap();
    for secret in [
        UUID,
        PBK,
        "ab12cd34",
        "de.example.com",
        "microsoft",
        "svcname",
        "cdn.example",
        "auth.example",
        "/secret",
        "vless://",
    ] {
        assert!(!json.contains(secret), "{secret} left in {json}");
    }
    assert_eq!(r.name, "DE-1", "names stay");
    assert_eq!(r.port, 443, "ports stay");
    assert_eq!(r.address, "***.com");
    assert_eq!(r.tls.fingerprint, "chrome");
}
