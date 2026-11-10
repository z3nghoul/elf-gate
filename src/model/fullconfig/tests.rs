use super::*;
use crate::parser::parse_link;
use crate::parser::subscription::parse_body;
use crate::storage::CoreConfig;
use crate::xray::config::build;
use serde_json::json;

const ID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const KEY: &str = "4GObrWHDR0TyD84iQ06z24v4YBxQ69vxeG1MCqOyFlI";

/// proxy (Reality) dials through hop (gRPC) which dials through a fragmenting freedom.
pub(crate) fn chain_dialer() -> Value {
    json!({
        "remarks": "🇫🇮 Chain",
        "outbounds": [
            {
                "tag": "proxy", "protocol": "vless",
                "settings": { "vnext": [{ "address": "exit.example.com", "port": 443,
                    "users": [{ "id": ID, "encryption": "none", "flow": "xtls-rprx-vision" }] }] },
                "streamSettings": {
                    "network": "tcp", "security": "reality",
                    "realitySettings": { "serverName": "www.example.org", "fingerprint": "chrome",
                        "publicKey": KEY, "shortId": "ab12" },
                    "sockopt": { "dialerProxy": "hop" }
                }
            },
            {
                "tag": "hop", "protocol": "vless",
                "settings": { "vnext": [{ "address": "hop.example.com", "port": 8443,
                    "users": [{ "id": ID, "encryption": "none" }] }] },
                "streamSettings": {
                    "network": "grpc", "security": "tls",
                    "tlsSettings": { "serverName": "hop.example.com" },
                    "grpcSettings": { "serviceName": "svc" },
                    "sockopt": { "dialerProxy": "frag" }
                }
            },
            { "tag": "frag", "protocol": "freedom",
              "settings": { "fragment": { "packets": "tlshello", "length": "100-200", "interval": "10-20" } } },
            { "tag": "direct", "protocol": "freedom" },
            { "tag": "block", "protocol": "blackhole" }
        ],
        "routing": { "rules": [
            { "type": "field", "domain": ["geosite:category-ads"], "outboundTag": "block" },
            { "type": "field", "network": "tcp,udp", "outboundTag": "proxy" }
        ] },
        "dns": { "servers": ["1.1.1.1"] }
    })
}

/// The older way to chain: `proxySettings.tag`.
fn chain_proxy_settings() -> Value {
    json!({
        "remarks": "Legacy chain",
        "outbounds": [
            { "tag": "exit", "protocol": "vless",
              "settings": { "vnext": [{ "address": "exit2.example.com", "port": 443, "users": [{ "id": ID, "encryption": "none" }] }] },
              "streamSettings": { "network": "tcp", "security": "tls", "tlsSettings": { "serverName": "exit2.example.com" } },
              "proxySettings": { "tag": "entry" } },
            { "tag": "entry", "protocol": "vless",
              "settings": { "vnext": [{ "address": "entry2.example.com", "port": 443, "users": [{ "id": ID, "encryption": "none" }] }] },
              "streamSettings": { "network": "tcp", "security": "tls", "tlsSettings": { "serverName": "entry2.example.com" } } },
            { "tag": "direct", "protocol": "freedom" }
        ],
        "routing": { "rules": [ { "type": "field", "outboundTag": "exit" } ] }
    })
}

/// Two exits behind a balancer with an observatory.
pub(crate) fn balanced() -> Value {
    let ob = |tag: &str, host: &str| {
        json!({
            "tag": tag, "protocol": "vless",
            "settings": { "address": host, "port": 443, "id": ID, "encryption": "none" },
            "streamSettings": { "network": "tcp", "security": "tls", "tlsSettings": { "serverName": host } }
        })
    };
    json!({
        "remarks": "Balanced",
        "outbounds": [ ob("proxy-a", "a.example.com"), ob("proxy-b", "b.example.com"), { "tag": "direct", "protocol": "freedom" } ],
        "observatory": { "subjectSelector": ["proxy-"], "probeUrl": "https://www.gstatic.com/generate_204", "probeInterval": "30s" },
        "routing": {
            "balancers": [ { "tag": "bal", "selector": ["proxy-"], "strategy": { "type": "leastPing" } } ],
            "rules": [ { "type": "field", "network": "tcp,udp", "balancerTag": "bal" } ]
        }
    })
}

fn separator() -> Value {
    json!({ "remarks": "⬇ Обход глушилок ⬇", "outbounds": [ { "tag": "direct", "protocol": "freedom" } ] })
}

fn stub_json() -> Value {
    json!({
        "remarks": "Включите HWID",
        "outbounds": [ { "tag": "proxy", "protocol": "vless",
            "settings": { "vnext": [{ "address": "0.0.0.0", "port": 1,
                "users": [{ "id": "00000000-0000-0000-0000-000000000000" }] }] } } ]
    })
}

pub(crate) fn fixtures() -> Vec<(&'static str, Value)> {
    vec![
        ("chain_dialer", chain_dialer()),
        ("chain_proxy_settings", chain_proxy_settings()),
        ("balanced", balanced()),
    ]
}

#[test]
fn a_dialer_chain_is_kept_whole_with_the_first_hop_as_the_address() {
    let s = parse_entry(&chain_dialer()).unwrap();
    assert_eq!(s.name, "🇫🇮 Chain");
    assert!(!s.info_only && s.unsupported.is_none());
    let full = s.full.as_ref().unwrap();
    assert_eq!(full.main, Target::Outbound("proxy".into()));
    assert_eq!(full.hops, 2, "two vless hops");
    assert_eq!(
        full.outbounds.len(),
        3,
        "proxy, hop and the fragmenting freedom"
    );
    // The machine connects to the END of the dialer chain first, so that is what a TCP ping
    // measures and what the tunnel must be kept away from.
    assert_eq!((s.address.as_str(), s.port), ("hop.example.com", 8443));
    assert_eq!(full.hosts(), ["exit.example.com", "hop.example.com"]);
    assert_eq!(s.security, Security::Reality);
    assert_eq!(s.flow, "xtls-rprx-vision");
}

#[test]
fn renaming_keeps_everything_inside_the_outbounds_and_follows_the_references() {
    let s = parse_entry(&chain_dialer()).unwrap();
    let full = s.full.unwrap();
    let r = full.renamed(&HashMap::new());
    let tags: Vec<_> = r
        .outbounds
        .iter()
        .map(|o| o["tag"].as_str().unwrap())
        .collect();
    assert_eq!(
        tags,
        ["proxy", "pv-hop", "pv-frag"],
        "the entry point is first and named proxy"
    );
    assert_eq!(
        r.outbounds[0]["streamSettings"]["sockopt"]["dialerProxy"],
        "pv-hop"
    );
    assert_eq!(
        r.outbounds[1]["streamSettings"]["sockopt"]["dialerProxy"],
        "pv-frag"
    );
    // Nothing else is touched: grpc stays grpc, the fragment stays as the provider wrote it.
    assert_eq!(
        r.outbounds[1]["streamSettings"]["grpcSettings"],
        json!({ "serviceName": "svc" })
    );
    assert_eq!(
        r.outbounds[2]["settings"]["fragment"],
        json!({ "packets": "tlshello", "length": "100-200", "interval": "10-20" })
    );
    assert!(!r.balanced);
}

#[test]
fn the_older_proxy_settings_chain_is_followed_too() {
    let s = parse_entry(&chain_proxy_settings()).unwrap();
    let full = s.full.as_ref().unwrap();
    assert_eq!(full.main, Target::Outbound("exit".into()));
    assert_eq!(
        s.address, "entry2.example.com",
        "the first hop is the entry"
    );
    let r = full.renamed(&HashMap::new());
    assert_eq!(r.outbounds[0]["tag"], "proxy");
    // Xray 26 removed `proxySettings`; the same chain is written as the dialer.
    assert!(r.outbounds[0].get("proxySettings").is_none());
    assert_eq!(
        r.outbounds[0]["streamSettings"]["sockopt"]["dialerProxy"],
        "pv-entry"
    );
    assert_eq!(
        r.outbounds[0]["streamSettings"]["tlsSettings"]["serverName"],
        "exit2.example.com"
    );
}

#[test]
fn a_balancer_becomes_the_entry_point_with_its_selector_and_observatory_renamed() {
    let s = parse_entry(&balanced()).unwrap();
    let full = s.full.as_ref().unwrap();
    assert_eq!(full.main, Target::Balancer("bal".into()));
    assert_eq!(full.hops, 2);
    let r = full.renamed(&HashMap::new());
    assert!(r.balanced);
    assert_eq!(r.balancers[0]["tag"], "proxy");
    assert_eq!(r.balancers[0]["selector"], json!(["pv-proxy-"]));
    let (key, obs) = r.observatory.unwrap();
    assert_eq!(key, "observatory");
    assert_eq!(obs["subjectSelector"], json!(["pv-proxy-"]));
    let tags: Vec<_> = r
        .outbounds
        .iter()
        .map(|o| o["tag"].as_str().unwrap())
        .collect();
    assert_eq!(tags, ["pv-proxy-a", "pv-proxy-b"]);
}

#[test]
fn the_final_config_routes_our_rules_into_the_chain_or_the_balancer() {
    let core = CoreConfig::default();
    let chain = build(&parse_entry(&chain_dialer()).unwrap(), &core).unwrap();
    assert_eq!(chain["outbounds"][0]["tag"], "proxy");
    let tags: Vec<_> = chain["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["tag"].as_str().unwrap())
        .collect();
    assert!(
        tags.contains(&"direct") && tags.contains(&"block") && tags.contains(&"pv-hop"),
        "{tags:?}"
    );
    assert!(chain.get("dns").is_none(), "the provider's dns is not used");
    assert!(
        chain["routing"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["outboundTag"] != "block" || r.get("domain").is_none()),
        "the provider's routing is not copied"
    );

    let bal = build(&parse_entry(&balanced()).unwrap(), &core).unwrap();
    assert_eq!(bal["routing"]["balancers"][0]["tag"], "proxy");
    assert_eq!(bal["observatory"]["subjectSelector"], json!(["pv-proxy-"]));
    for r in bal["routing"]["rules"].as_array().unwrap() {
        assert_ne!(r["outboundTag"], "proxy", "{r}");
    }
    assert!(bal["routing"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["balancerTag"] == "proxy" && r["network"] == "tcp,udp"));
}

#[test]
fn separators_and_placeholders_are_notices_not_servers() {
    let sep = parse_entry(&separator()).unwrap();
    assert!(sep.info_only && sep.unsupported.is_some());
    assert_eq!(sep.name, "⬇ Обход глушилок ⬇");
    let stub = parse_entry(&stub_json()).unwrap();
    assert!(stub.info_only);
    assert!(stub.unsupported.as_ref().unwrap().contains("HWID"));
    assert!(
        build(&stub, &CoreConfig::default()).is_err(),
        "never started"
    );
}

#[test]
fn placeholders_are_recognised_in_every_format() {
    // The same placeholder as a plain share link.
    let s = parse_link(
        "vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?security=none#Используйте%20Happ",
    )
    .unwrap();
    assert!(s.info_only);
    assert_eq!(s.name, "Используйте Happ");
    // A normal link is untouched.
    assert!(
        !parse_link(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@h.example.com:443?security=tls#ok"
        )
        .unwrap()
        .info_only
    );
    assert!(
        is_stub("host", 0, ID)
            && is_stub("0.0.0.0", 443, ID)
            && is_stub("h", 443, "00000000-0000-0000-0000-000000000000")
    );
    assert!(!is_stub("h.example.com", 443, ID));
}

#[test]
fn a_json_subscription_gives_servers_titles_and_notices_in_order() {
    let body = serde_json::to_string(&json!([
        separator(),
        chain_dialer(),
        balanced(),
        stub_json()
    ]))
    .unwrap();
    let p = parse_body(&body).unwrap();
    let kinds: Vec<_> = p
        .servers
        .iter()
        .map(|s| (s.name.as_str(), s.info_only))
        .collect();
    assert_eq!(
        kinds,
        [
            ("⬇ Обход глушилок ⬇", true),
            ("🇫🇮 Chain", false),
            ("Balanced", false),
            ("Включите HWID", true)
        ]
    );
    // base64-wrapped JSON works too.
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&body);
    assert_eq!(parse_body(&b64).unwrap().servers.len(), 4);
}

#[test]
fn an_entry_survives_the_cache_as_a_link_and_the_interface_never_sees_keys() {
    let s = parse_entry(&chain_dialer()).unwrap();
    assert!(s.link.starts_with(LINK_PREFIX));
    let again = parse_link(&s.link).unwrap();
    assert_eq!(again.full, s.full);
    let red = serde_json::to_string(&s.redacted()).unwrap();
    for secret in [ID, KEY, "ab12", "xrayjson:"] {
        assert!(!red.contains(secret), "{secret} leaked");
    }
    assert!(red.contains("hop.example.com"), "the address is shown");
}

#[test]
fn tun_pins_host_names_to_addresses_and_keeps_the_name_for_tls() {
    let s = parse_entry(&chain_dialer()).unwrap();
    let mut pin = HashMap::new();
    pin.insert("hop.example.com".to_string(), "203.0.113.7".to_string());
    pin.insert("exit.example.com".to_string(), "203.0.113.8".to_string());
    let r = s.full.unwrap().renamed(&pin);
    assert_eq!(
        r.outbounds[1]["settings"]["vnext"][0]["address"],
        "203.0.113.7"
    );
    assert_eq!(
        r.outbounds[1]["streamSettings"]["tlsSettings"]["serverName"],
        "hop.example.com"
    );
    assert_eq!(
        r.outbounds[0]["settings"]["vnext"][0]["address"],
        "203.0.113.8"
    );
    assert_eq!(
        r.outbounds[0]["streamSettings"]["realitySettings"]["serverName"], "www.example.org",
        "an existing server name is kept"
    );
}
