//! Builds the Xray JSON configuration from a server and the core settings.

use crate::model::server::{Security, Server, Transport};
use crate::storage::CoreConfig;
use serde_json::{json, Map, Value};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("сервер «{0}» не поддерживается: {1}")]
    Unsupported(String, String),
}

/// Inserts `key` only when the value is not empty.
fn put(map: &mut Map<String, Value>, key: &str, value: &str) {
    if !value.is_empty() {
        map.insert(key.into(), json!(value));
    }
}

fn stream_settings(s: &Server) -> Value {
    let mut stream = Map::new();
    let network = match s.transport {
        Transport::Tcp => "tcp",
        Transport::Xhttp => "xhttp",
        Transport::Grpc => "grpc",
        Transport::Ws => "ws",
    };
    stream.insert("network".into(), json!(network));

    match s.security {
        Security::None => {
            stream.insert("security".into(), json!("none"));
        }
        Security::Tls => {
            stream.insert("security".into(), json!("tls"));
            let mut tls = Map::new();
            put(&mut tls, "serverName", &s.tls.sni);
            put(&mut tls, "fingerprint", &s.tls.fingerprint);
            if !s.tls.alpn.is_empty() {
                tls.insert("alpn".into(), json!(s.tls.alpn));
            }
            if s.tls.allow_insecure {
                tls.insert("allowInsecure".into(), json!(true));
            }
            stream.insert("tlsSettings".into(), Value::Object(tls));
        }
        Security::Reality => {
            stream.insert("security".into(), json!("reality"));
            let mut r = Map::new();
            put(&mut r, "serverName", &s.tls.sni);
            // Reality requires a fingerprint; chrome is the common default.
            let fp = if s.tls.fingerprint.is_empty() {
                "chrome"
            } else {
                &s.tls.fingerprint
            };
            r.insert("fingerprint".into(), json!(fp));
            put(&mut r, "publicKey", &s.tls.public_key);
            put(&mut r, "shortId", &s.tls.short_id);
            put(&mut r, "spiderX", &s.tls.spider_x);
            stream.insert("realitySettings".into(), Value::Object(r));
        }
    }

    let path_or_root = if s.params.path.is_empty() {
        "/"
    } else {
        &s.params.path
    };
    match s.transport {
        Transport::Tcp => {}
        Transport::Ws => {
            let mut ws = Map::new();
            ws.insert("path".into(), json!(path_or_root));
            // `headers.Host` is deprecated in Xray 26.x in favour of `host`.
            put(&mut ws, "host", &s.params.host);
            stream.insert("wsSettings".into(), Value::Object(ws));
        }
        Transport::Grpc => {
            let mut grpc = Map::new();
            grpc.insert("serviceName".into(), json!(s.params.service_name));
            stream.insert("grpcSettings".into(), Value::Object(grpc));
        }
        Transport::Xhttp => {
            let mut x = Map::new();
            x.insert("path".into(), json!(path_or_root));
            put(&mut x, "host", &s.params.host);
            put(&mut x, "mode", &s.params.mode);
            stream.insert("xhttpSettings".into(), Value::Object(x));
        }
    }
    Value::Object(stream)
}

fn proxy_outbound(s: &Server) -> Value {
    let mut user = Map::new();
    user.insert("id".into(), json!(s.uuid));
    user.insert("encryption".into(), json!("none"));
    put(&mut user, "flow", &s.flow);
    json!({
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": s.address,
                "port": s.port,
                "users": [Value::Object(user)],
            }]
        },
        "streamSettings": stream_settings(s),
    })
}

/// Server + settings -> Xray configuration.
pub fn build(server: &Server, core: &CoreConfig) -> Result<Value, ConfigError> {
    if let Some(reason) = &server.unsupported {
        return Err(ConfigError::Unsupported(
            server.name.clone(),
            reason.clone(),
        ));
    }
    let sniffing = json!({
        "enabled": true,
        "destOverride": ["http", "tls", "quic"],
    });
    Ok(json!({
        "log": { "loglevel": core.log_level },
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": core.socks_port,
                "protocol": "socks",
                "settings": { "auth": "noauth", "udp": true, "ip": "127.0.0.1" },
                "sniffing": sniffing,
            },
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": core.http_port,
                "protocol": "http",
                "settings": {},
                "sniffing": sniffing,
            },
        ],
        "outbounds": [
            proxy_outbound(server),
            { "tag": "direct", "protocol": "freedom" },
            { "tag": "block", "protocol": "blackhole" },
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                // User rules are added in stage 7.
                { "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" },
            ],
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_link;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn config_for(link: &str) -> Value {
        build(&parse_link(link).unwrap(), &CoreConfig::default()).unwrap()
    }

    #[test]
    fn reality_tcp_vision() {
        insta::assert_json_snapshot!(config_for(&format!(
            "vless://{UUID}@de.example.com:443?flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=4GObrWHDR0TyD84iQ06z24v4YBxQ69vxeG1MCqOyFlI&sid=ab12cd34&spx=%2F&type=tcp#DE-1"
        )));
    }

    #[test]
    fn reality_xhttp() {
        insta::assert_json_snapshot!(config_for(&format!(
            "vless://{UUID}@nl.example.com:443?security=reality&sni=example.org&fp=firefox&pbk=4GObrWHDR0TyD84iQ06z24v4YBxQ69vxeG1MCqOyFlI&sid=0123abcd&type=xhttp&path=%2Fxh&host=cdn.example.org&mode=packet-up#NL-2"
        )));
    }

    #[test]
    fn tls_ws() {
        insta::assert_json_snapshot!(config_for(&format!(
            "vless://{UUID}@fi.example.com:8443?security=tls&sni=fi.example.com&alpn=h2%2Chttp%2F1.1&fp=chrome&type=ws&path=%2Fws&host=fi.example.com#FI-1"
        )));
    }

    #[test]
    fn tls_grpc() {
        insta::assert_json_snapshot!(config_for(&format!(
            "vless://{UUID}@g.example.com:443?security=tls&sni=g.example.com&type=grpc&serviceName=svc#G"
        )));
    }

    #[test]
    fn plain_tcp_private_ipv6() {
        // Xray refuses unencrypted VLESS to public IPs, so use a private address.
        insta::assert_json_snapshot!(config_for(&format!(
            "vless://{UUID}@[fd00::1]:2053?type=tcp#v6"
        )));
    }

    #[test]
    fn custom_ports_and_log_level() {
        let server = parse_link(&format!("vless://{UUID}@h.example.com:443#x")).unwrap();
        let core = CoreConfig {
            socks_port: 1111,
            http_port: 2222,
            log_level: "debug".into(),
            ..CoreConfig::default()
        };
        let cfg = build(&server, &core).unwrap();
        assert_eq!(cfg["log"]["loglevel"], "debug");
        assert_eq!(cfg["inbounds"][0]["port"], 1111);
        assert_eq!(cfg["inbounds"][1]["port"], 2222);
        assert_eq!(cfg["inbounds"][0]["settings"]["udp"], true);
    }

    #[test]
    fn unsupported_server_is_rejected() {
        let server = parse_link("trojan://p@h:443#t").unwrap();
        assert!(matches!(
            build(&server, &CoreConfig::default()),
            Err(ConfigError::Unsupported(..))
        ));
    }

    /// Runs every fixture through a real Xray (`xray run -test`).
    /// Skipped unless `ELF_GATE_XRAY` points to the binary; the `.dat` files
    /// are looked up next to it.
    #[test]
    fn generated_configs_pass_xray_test() {
        let Ok(xray) = std::env::var("ELF_GATE_XRAY") else {
            eprintln!("ELF_GATE_XRAY not set, skipping");
            return;
        };
        let xray = std::path::PathBuf::from(xray);
        let asset_dir = xray.parent().unwrap().to_path_buf();
        let key = "4GObrWHDR0TyD84iQ06z24v4YBxQ69vxeG1MCqOyFlI";
        let links = [
            format!("vless://{UUID}@de.example.com:443?flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk={key}&sid=ab12cd34&type=tcp#a"),
            format!("vless://{UUID}@nl.example.com:443?security=reality&sni=example.org&pbk={key}&sid=0123abcd&type=xhttp&path=%2Fxh&host=cdn.example.org&mode=packet-up#b"),
            format!("vless://{UUID}@fi.example.com:8443?security=tls&sni=fi.example.com&alpn=h2%2Chttp%2F1.1&type=ws&path=%2Fws&host=fi.example.com#c"),
            format!("vless://{UUID}@g.example.com:443?security=tls&sni=g.example.com&type=grpc&serviceName=svc#d"),
            format!("vless://{UUID}@[fd00::1]:2053?type=tcp#e"),
        ];
        for (i, link) in links.iter().enumerate() {
            let path = std::env::temp_dir().join(format!(
                "elf-gate-xray-test-{}-{i}.json",
                std::process::id()
            ));
            std::fs::write(&path, serde_json::to_vec_pretty(&config_for(link)).unwrap()).unwrap();
            let out = std::process::Command::new(&xray)
                .args(["run", "-test", "-c"])
                .arg(&path)
                .env("XRAY_LOCATION_ASSET", &asset_dir)
                .output()
                .unwrap();
            let _ = std::fs::remove_file(&path);
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success() && text.contains("Configuration OK"),
                "{link}\n{text}"
            );
        }
    }
}
