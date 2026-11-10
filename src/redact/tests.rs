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
        "from tcp:*.*.*.*:58460 accepted tcp:***:80 [socks-in -> proxy]"
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
        "proxy/vless/outbound: failed to dial ***:8443 > EOF"
    );
    assert_eq!(
        full("from [2001:db8::5]:5555 accepted"),
        "from [*:*:*:*]:5555 accepted"
    );
    assert_eq!(
        full("rule full:example.org -> direct"),
        "rule full:*** -> direct"
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
    assert_eq!(host("vpn.example.co.uk"), "***");
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
    assert_eq!(r.address, "***");
    assert_eq!(r.tls.fingerprint, "chrome");
}

#[test]
fn typical_xray_warnings_and_errors_leave_no_address_domain_or_home() {
    let lines = [
        // deprecated / migration warnings keep their words
        r#"2026/11/10 15:46:27 [Warning] infra/conf: The feature "proxySettings" has been removed and migrated to "streamSettings.sockopt.dialerProxy". Please update your config(s)"#,
        "[Warning] core: Xray 26.11.9 started, transport grpc is deprecated",
        // dial / handshake errors with addresses
        "[Info] proxy/vless/outbound: failed to find an available destination > common/retry: [transport/internet/tcp: failed to dial to dest: tcp:vpn.example.net:443 > dial tcp 203.0.113.9:443: i/o timeout] > common/retry: all retry attempts failed",
        "[Warning] REALITY: processed invalid connection from 198.51.100.7:5555: failed to read client hello",
        "[Error] transport/internet/tcp: failed to dial to [2001:db8::7]:8443: connect: network is unreachable",
        "[Error] proxy/vless/outbound: tls handshake with exit.example.org:443: x509: certificate is valid for www.example.com, not exit.example.org",
        // DNS errors with a domain
        "[Warning] app/dns: failed to lookup ip for domain panel.example.org > lookup panel.example.org on 192.168.1.1:53: no such host",
        "[Error] app/dns: UDP:1.1.1.1:53 got answer: gstatic.com. A > rcode: 2",
        // paths with the account name
        "Reading config: &{Name:/home/z3n/.local/state/elf-gate/run/xray.json Format:json}",
        r#"Failed to start: open C:\Users\Anna\AppData\Roaming\elf-gate\run\xray.json: access denied"#,
        "stat /root/.config/elf-gate/config.toml: permission denied",
        "xray: /Users/bob/bin/xray, ассеты: /Users/bob/bin (geoip.dat: есть)",
    ];
    for line in lines {
        let out = full(line);
        for secret in [
            "203.0.113.9",
            "198.51.100.7",
            "2001:db8",
            "192.168.1.1",
            "1.1.1.1",
            "vpn.example",
            "exit.example",
            "example.org",
            "example.com",
            "panel.example",
            "gstatic",
            "z3n",
            "Anna",
            "bob",
            "/home/",
            "/root",
            "/Users/",
            "C:\\Users",
        ] {
            assert!(
                !out.contains(secret),
                "`{secret}` left in `{out}` (from `{line}`)"
            );
        }
        // (`***.` before a space is the end of a sentence; before a letter it would be a zone.)
        assert!(
            !out.match_indices("***.").any(|(i, _)| out[i + 4..]
                .chars()
                .next()
                .is_some_and(char::is_alphanumeric)),
            "a half-hidden name in `{out}`"
        );
    }
    // The words of the message stay, so the line is still readable.
    assert!(full(lines[0]).contains("proxySettings") && full(lines[0]).contains("dialerProxy"));
    assert!(full(lines[2]).contains("i/o timeout") && full(lines[2]).contains(":443"));
    assert!(
        full(lines[3]).contains("failed to read client hello") && full(lines[3]).contains(":5555")
    );
    assert!(full(lines[6]).contains("no such host") && full(lines[6]).contains(":53"));
    assert_eq!(
        full("Reading config: &{Name:/home/z3n/.local/state/elf-gate/run/xray.json Format:json}"),
        "Reading config: &{Name:~/.local/state/elf-gate/run/xray.json Format:json}"
    );
    // File logs keep addresses and paths (only secrets go): the home is a screen matter.
    assert!(text("open /home/z3n/x.json", Mode::Secrets).contains("/home/z3n"));
}

#[test]
fn home_directories_become_a_tilde_in_every_form() {
    assert_eq!(
        strip_home("/home/z3n/.config/elf-gate"),
        "~/.config/elf-gate"
    );
    assert_eq!(strip_home("cwd=/home/z3n"), "cwd=~");
    assert_eq!(strip_home(r"C:\Users\Anna\AppData"), r"~\AppData");
    assert_eq!(strip_home("/Users/bob/bin"), "~/bin");
    assert_eq!(
        strip_home("/root/x and /rootkit"),
        "~/x and /rootkit",
        "only /root as a whole word"
    );
    assert_eq!(
        strip_home("/usr/local/lib/elf-gate/xray"),
        "/usr/local/lib/elf-gate/xray"
    );
    assert_eq!(strip_home("two /home/a/x and /home/b/y"), "two ~/x and ~/y");
}
