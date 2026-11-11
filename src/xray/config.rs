//! Builds the Xray JSON configuration from a server and the core settings.

use crate::model::rule::{EffectiveRules, RoutingMode, TrafficMode};
use crate::model::server::{Security, Server, Transport};
use crate::storage::CoreConfig;
use serde_json::{json, Map, Value};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{}", crate::t!("err.server_unsupported", name = .0, reason = .1))]
    Unsupported(String, String),
}

/// Inserts `key` only when the value is not empty.
fn put(map: &mut Map<String, Value>, key: &str, value: &str) {
    if !value.is_empty() {
        map.insert(key.into(), json!(value));
    }
}

/// `fallback`: the server's domain name when the config dials a pre-resolved IP instead, so
/// TLS and HTTP-level host names still say what they said in the link.
fn stream_settings(s: &Server, fallback: Option<&str>) -> Value {
    let sni = if s.tls.sni.is_empty() {
        fallback.unwrap_or("")
    } else {
        &s.tls.sni
    };
    let host = if s.params.host.is_empty() {
        fallback.unwrap_or("")
    } else {
        &s.params.host
    };
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
            put(&mut tls, "serverName", sni);
            put(&mut tls, "fingerprint", s.effective_fingerprint());
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
            put(&mut r, "serverName", sni);
            // Reality requires a fingerprint; chrome is the common default.
            let fp = if s.effective_fingerprint().is_empty() {
                "chrome"
            } else {
                s.effective_fingerprint()
            };
            r.insert("fingerprint".into(), json!(fp));
            put(&mut r, "publicKey", &s.tls.public_key);
            put(&mut r, "shortId", &s.tls.short_id);
            put(&mut r, "spiderX", &s.tls.spider_x);
            stream.insert("realitySettings".into(), Value::Object(r));
        }
    }

    if fragments(s) {
        // The TCP connection to the server is opened through a `freedom` outbound that cuts
        // the TLS ClientHello into pieces (a DPI workaround, see `FRAGMENT_TAG`).
        stream.insert("sockopt".into(), json!({ "dialerProxy": FRAGMENT_TAG }));
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
            put(&mut ws, "host", host);
            stream.insert("wsSettings".into(), Value::Object(ws));
        }
        Transport::Grpc => {
            let mut grpc = Map::new();
            grpc.insert("serviceName".into(), json!(s.params.service_name));
            put(&mut grpc, "authority", &s.params.authority);
            // v2ray-style links say `mode=multi` for gRPC multi mode.
            if s.params.mode.eq_ignore_ascii_case("multi") {
                grpc.insert("multiMode".into(), json!(true));
            }
            stream.insert("grpcSettings".into(), Value::Object(grpc));
        }
        Transport::Xhttp => {
            let mut x = Map::new();
            x.insert("path".into(), json!(path_or_root));
            put(&mut x, "host", host);
            put(&mut x, "mode", &s.params.mode);
            if let Some(extra) = &s.params.extra {
                x.insert("extra".into(), extra.clone());
            }
            stream.insert("xhttpSettings".into(), Value::Object(x));
        }
    }
    Value::Object(stream)
}

/// Outbound that sends the ClientHello of a TLS or Reality connection in pieces.
pub const FRAGMENT_TAG: &str = "fragment";

/// ClientHello fragmentation applies to TLS and Reality only.
fn fragments(s: &Server) -> bool {
    s.fragment && matches!(s.security, Security::Tls | Security::Reality)
}

fn fragment_outbound() -> Value {
    json!({
        "tag": FRAGMENT_TAG,
        "protocol": "freedom",
        "settings": {
            "fragment": { "packets": "tlshello", "length": "100-200", "interval": "10-20" }
        },
    })
}

fn is_ip(addr: &str) -> bool {
    addr.parse::<std::net::IpAddr>().is_ok()
}

/// `address_override`: a pre-resolved IP of the server (TUN mode resolves it before the
/// tunnel exists, so Xray never has to resolve it through the tunnel).
fn proxy_outbound(s: &Server, address_override: Option<&str>, tag: &str) -> Value {
    let mut user = Map::new();
    user.insert("id".into(), json!(s.uuid));
    let encryption = if s.encryption.is_empty() {
        "none"
    } else {
        &s.encryption
    };
    user.insert("encryption".into(), json!(encryption));
    put(&mut user, "flow", &s.flow);
    let fallback = (address_override.is_some() && !is_ip(&s.address)).then_some(s.address.as_str());
    json!({
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": address_override.unwrap_or(&s.address),
                "port": s.port,
                "users": [Value::Object(user)],
            }]
        },
        "streamSettings": stream_settings(s, fallback),
    })
}

/// Process names of elf-gate itself (the TUI and the background part).
const SELF_PROCESSES: [&str; 2] = ["elf-gate", "elf-gated"];

/// What differs between the plain proxy config and a TUN config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunPlan {
    pub name: String,
    pub ipv6: bool,
    /// Windows-only leak protection (WFP filters) is added.
    pub windows: bool,
    /// Resolver for "through the VPN" names; reached through the tunnel.
    pub tunnel_dns: String,
    /// The system's upstream resolvers, for names that resolve locally. Empty disables DNS routing.
    pub local_dns: Vec<String>,
}

/// Tags used when a backup server exists (the "primary + backup" scheme).
pub const PRIMARY_TAG: &str = "proxy-primary";
pub const BACKUP_TAG: &str = "proxy-backup";

/// The backup half of the "primary + backup" scheme. Xray's own observatory probes both
/// servers; a balancer with a fallback sends traffic to the backup while the primary fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failover {
    pub backup: Server,
    /// Pre-resolved IP of the backup (TUN mode), like `Plan::vps_ip` for the primary.
    pub backup_ip: Option<String>,
    pub probe_url: String,
    /// Seconds between probes. Xray's observatory has no hysteresis of its own, so this
    /// interval is the damping: the primary is dropped after one failed probe and taken back
    /// after the next good one, never faster than one probe apart.
    pub interval_secs: u32,
}

impl Failover {
    pub fn new(backup: Server, backup_ip: Option<String>, probe_url: String) -> Self {
        Self {
            backup,
            backup_ip,
            probe_url,
            interval_secs: 10,
        }
    }
}

/// Everything beyond server and core settings that shapes the config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub traffic: TrafficMode,
    pub routing: RoutingMode,
    pub rules: EffectiveRules,
    pub tun: Option<TunPlan>,
    pub vps_ip: Option<String>,
    pub failover: Option<Failover>,
    /// TUN: addresses that must never enter the tunnel (every server in the list: pings and the
    /// connection itself, resolved before the tunnel exists) and host names of the same kind
    /// (servers, subscription URLs). They go direct whatever the process detection says.
    pub direct_ips: Vec<String>,
    pub direct_domains: Vec<String>,
    /// TUN, complete provider configs: host name -> address resolved before the tunnel exists.
    pub pin: std::collections::HashMap<String, String>,
}

impl Plan {
    /// Plain local proxy, no user rules: what the application did before TUN existed.
    pub fn proxy_default() -> Self {
        Plan {
            traffic: TrafficMode::Proxy,
            routing: RoutingMode::Exclude,
            rules: EffectiveRules {
                always_direct_ips: vec!["geoip:private".into()],
                ..EffectiveRules::default()
            },
            tun: None,
            vps_ip: None,
            failover: None,
            direct_ips: Vec::new(),
            direct_domains: Vec::new(),
            pin: std::collections::HashMap::new(),
        }
    }

    /// Domains that should resolve through the tunnel (include) or locally (exclude) need
    /// DNS routing; it also needs somewhere to resolve the rest.
    /// In TUN mode every DNS query is hijacked, so the built-in DNS is always there.
    fn dns_routing(&self) -> Option<(&TunPlan, &[String])> {
        let tun = self.tun.as_ref()?;
        Some((tun, self.rules.domains.as_slice()))
    }
}

fn tun_inbound(t: &TunPlan, sniffing: &Value) -> Value {
    let mut gateway = vec!["198.18.0.1/16".to_string()];
    let mut routes = vec!["0.0.0.0/0".to_string()];
    if t.ipv6 {
        gateway.push("fdfe:dcba:9876::1/64".into());
        routes.push("::/0".into());
    }
    let mut settings = json!({
        "name": t.name,
        "mtu": 1500,
        "gateway": gateway,
        "autoSystemRoutingTable": routes,
        // Binds Xray's own connections to the physical interface: no routing loop.
        "autoOutboundsInterface": "auto",
    });
    if t.windows {
        settings["desc"] = json!("elf-gate");
        // Block traffic of an IP version that has no route into the tunnel (a leak).
        settings["autoSystemWfpBlockLeak"] = json!(["misconfigtun"]);
    }
    json!({
        "tag": "tun-in",
        "protocol": "tun",
        "settings": settings,
        "sniffing": sniffing,
    })
}

/// DNS-over-HTTPS endpoints of well-known public resolvers.
fn doh_url(ip: &str) -> Option<&'static str> {
    Some(match ip {
        "1.1.1.1" | "1.0.0.1" => "https://1.1.1.1/dns-query",
        "8.8.8.8" | "8.8.4.4" => "https://8.8.8.8/dns-query",
        "9.9.9.9" => "https://9.9.9.9/dns-query",
        _ => return None,
    })
}

/// Resolvers reached through the tunnel: DoH (or DNS over TCP), never plain UDP, which some
/// servers do not pass. The second one is a fallback.
fn tunnel_servers(tunnel_dns: &str) -> Vec<Value> {
    let primary = if tunnel_dns.starts_with("https://") || tunnel_dns.starts_with("tcp://") {
        tunnel_dns.to_string()
    } else if tunnel_dns.is_empty() {
        "https://1.1.1.1/dns-query".to_string()
    } else {
        doh_url(tunnel_dns).map_or_else(|| format!("tcp://{tunnel_dns}"), str::to_string)
    };
    let mut addresses = vec![primary];
    let fallback = "https://8.8.8.8/dns-query".to_string();
    if !addresses.contains(&fallback) {
        addresses.push(fallback);
    }
    addresses
        .into_iter()
        .enumerate()
        .map(|(i, a)| json!({ "address": a, "tag": tunnel_tag(i) }))
        .collect()
}

fn tunnel_tag(i: usize) -> String {
    if i == 0 {
        "dns-tunnel".into()
    } else {
        format!("dns-tunnel-{i}")
    }
}

fn dns_section(plan: &Plan, t: &TunPlan, listed: &[String]) -> (Value, Vec<Value>) {
    let tunnel = tunnel_servers(&t.tunnel_dns);
    let tunnel_tags: Vec<String> = (0..tunnel.len()).map(tunnel_tag).collect();
    let locals: Vec<Value> = t
        .local_dns
        .iter()
        .enumerate()
        .map(|(i, a)| json!({ "address": a, "port": 53, "tag": format!("dns-local-{i}") }))
        .collect();
    // The listed names use one resolver exclusively; every other name uses the other side.
    // Without listed names or without a system resolver everything goes through the tunnel.
    let restrict = |mut server: Value| {
        server["domains"] = json!(listed);
        server["skipFallback"] = json!(true);
        server
    };
    let split = !listed.is_empty() && !locals.is_empty();
    let (servers, local_tags): (Vec<Value>, Vec<String>) = if !split {
        (tunnel, Vec::new())
    } else {
        let tags = (0..t.local_dns.len())
            .map(|i| format!("dns-local-{i}"))
            .collect();
        let servers = match plan.routing {
            RoutingMode::Include => tunnel.into_iter().map(restrict).chain(locals).collect(),
            RoutingMode::Exclude => locals.into_iter().map(restrict).chain(tunnel).collect(),
        };
        (servers, tags)
    };
    // Every query to port 53 (any destination, private ones too) is answered by the built-in
    // DNS, ahead of every other rule: a resolver on the LAN or at the provider must not be
    // reached around the tunnel. The resolver's own connections are routed by their tags.
    let mut rules = vec![
        json!({ "type": "field", "inboundTag": ["tun-in"], "network": "tcp,udp", "port": "53", "outboundTag": "dns-out" }),
        json!({ "type": "field", "inboundTag": tunnel_tags, "outboundTag": "proxy" }),
    ];
    if !local_tags.is_empty() {
        rules.push(json!({ "type": "field", "inboundTag": local_tags, "outboundTag": "direct" }));
    }
    (
        json!({ "servers": servers, "queryStrategy": "UseIP" }),
        rules,
    )
}

/// Server + settings -> Xray configuration (plain local proxy, no user rules).
pub fn build(server: &Server, core: &CoreConfig) -> Result<Value, ConfigError> {
    build_with(server, core, &Plan::proxy_default())
}

/// Server + settings + routing plan -> Xray configuration.
pub fn build_with(server: &Server, core: &CoreConfig, plan: &Plan) -> Result<Value, ConfigError> {
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
    let mut inbounds = vec![
        json!({
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": core.socks_port,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": true, "ip": "127.0.0.1" },
            "sniffing": sniffing,
        }),
        json!({
            "tag": "http-in",
            "listen": "127.0.0.1",
            "port": core.http_port,
            "protocol": "http",
            "settings": {},
            "sniffing": sniffing,
        }),
    ];
    if let Some(t) = &plan.tun {
        inbounds.push(tun_inbound(t, &sniffing));
    }

    // A complete provider config: its outbounds (the whole chain) are carried over as they are.
    let full = server.full.as_ref().map(|f| f.renamed(&plan.pin));
    let primary_tag = if plan.failover.is_some() {
        PRIMARY_TAG
    } else {
        "proxy"
    };
    let mut outbounds = match &full {
        Some(parts) => {
            let mut o = parts.outbounds.clone();
            o.push(json!({ "tag": "direct", "protocol": "freedom" }));
            o.push(json!({ "tag": "block", "protocol": "blackhole" }));
            o
        }
        None => vec![
            proxy_outbound(server, plan.vps_ip.as_deref(), primary_tag),
            json!({ "tag": "direct", "protocol": "freedom" }),
            json!({ "tag": "block", "protocol": "blackhole" }),
        ],
    };
    let full_balanced = full.as_ref().is_some_and(|p| p.balanced);
    if let Some(f) = plan.failover.as_ref().filter(|_| full.is_none()) {
        if let Some(reason) = &f.backup.unsupported {
            return Err(ConfigError::Unsupported(
                f.backup.name.clone(),
                reason.clone(),
            ));
        }
        outbounds.insert(
            1,
            proxy_outbound(&f.backup, f.backup_ip.as_deref(), BACKUP_TAG),
        );
    }

    let backup_fragments = plan.failover.as_ref().is_some_and(|f| fragments(&f.backup));
    if full.is_none() && (fragments(server) || backup_fragments) {
        outbounds.push(fragment_outbound());
    }

    let mut rules: Vec<Value> = Vec::new();
    let mut dns = None;
    if let Some((t, listed)) = plan.dns_routing() {
        let (section, dns_rules) = dns_section(plan, t, listed);
        dns = Some(section);
        outbounds.push(json!({ "tag": "dns-out", "protocol": "dns" }));
        rules.extend(dns_rules);
    }
    // The connection check must test the VPN itself, whatever the user's rules say.
    rules.push(json!({
        "type": "field",
        "inboundTag": ["socks-in"],
        "domain": [format!("full:{}", crate::net::health::HEALTH_HOST)],
        "outboundTag": "proxy",
    }));
    // Servers must never be reached through the tunnel (a routing loop: VPN inside the VPN).
    // Process detection can fail (no rights to read other processes' sockets), so this rule
    // does not depend on it.
    if plan.tun.is_some() && !plan.direct_ips.is_empty() {
        rules.push(json!({ "type": "field", "ip": plan.direct_ips, "outboundTag": "direct" }));
    }
    if plan.tun.is_some() && !plan.direct_domains.is_empty() {
        rules.push(
            json!({ "type": "field", "domain": plan.direct_domains, "outboundTag": "direct" }),
        );
    }
    // elf-gate's own traffic (subscription downloads) must not enter the tunnel in any routing
    // mode: a subscription host may be blocked, and the tunnel may be down while we update.
    if plan.tun.is_some() {
        rules.push(json!({ "type": "field", "process": SELF_PROCESSES, "outboundTag": "direct" }));
    }
    if plan.rules.block_udp443 {
        rules.push(
            json!({ "type": "field", "network": "udp", "port": "443", "outboundTag": "block" }),
        );
    }
    if !plan.rules.always_direct_ips.is_empty() {
        rules.push(
            json!({ "type": "field", "ip": plan.rules.always_direct_ips, "outboundTag": "direct" }),
        );
    }
    // `exclude`: listed things stay direct, the rest uses the VPN (the first outbound).
    // `include`: listed things use the VPN, the rest stays direct.
    let target = match plan.routing {
        RoutingMode::Exclude => "direct",
        RoutingMode::Include => "proxy",
    };
    // Process names only mean something for traffic that comes from this machine's apps
    // through the TUN; in proxy mode they stay inactive.
    if plan.tun.is_some() && !plan.rules.processes.is_empty() {
        rules.push(
            json!({ "type": "field", "process": plan.rules.processes, "outboundTag": target }),
        );
    }
    if !plan.rules.domains.is_empty() {
        rules.push(json!({ "type": "field", "domain": plan.rules.domains, "outboundTag": target }));
    }
    if !plan.rules.ips.is_empty() {
        rules.push(json!({ "type": "field", "ip": plan.rules.ips, "outboundTag": target }));
    }
    if plan.routing == RoutingMode::Include {
        rules.push(json!({ "type": "field", "network": "tcp,udp", "outboundTag": "direct" }));
    }

    let mut balancers = Vec::new();
    if let Some(parts) = full.as_ref().filter(|p| p.balanced) {
        balancers.extend(parts.balancers.clone());
    }
    if plan.failover.is_some() && full.is_none() || full_balanced {
        // Everything that used the "proxy" outbound now goes through the balancer of the same
        // name: the primary while the observatory says it is alive, else the backup.
        for rule in &mut rules {
            if rule["outboundTag"] == "proxy" {
                if let Some(obj) = rule.as_object_mut() {
                    obj.remove("outboundTag");
                    obj.insert("balancerTag".into(), json!("proxy"));
                }
            }
        }
        if plan.routing == RoutingMode::Exclude {
            // Without a rule the default (first) outbound would be used, which is the primary
            // only: unmatched traffic must see the balancer too.
            rules.push(json!({ "type": "field", "network": "tcp,udp", "balancerTag": "proxy" }));
        }
        if !full_balanced {
            balancers.push(json!({
                "tag": "proxy",
                "selector": [PRIMARY_TAG],
                "fallbackTag": BACKUP_TAG,
                "strategy": { "type": "leastPing" },
            }));
        }
    }

    // Traffic statistics for the interface (`xray api statsquery`); 0 turns them off
    // (temporary probe cores have no use for them and must not take the port).
    if core.api_port != 0 {
        inbounds.push(json!({
            "tag": "api",
            "listen": "127.0.0.1",
            "port": core.api_port,
            "protocol": "dokodemo-door",
            "settings": { "address": "127.0.0.1" },
        }));
        rules.insert(
            0,
            json!({ "type": "field", "inboundTag": ["api"], "outboundTag": "api" }),
        );
    }
    let mut config = json!({
        // Without `access` Xray prints every connection to the console: that stays off unless
        // the user asks for the detailed log.
        "log": if core.verbose_log {
            json!({ "loglevel": if core.log_level == "warning" { "info" } else { core.log_level.as_str() } })
        } else {
            json!({ "loglevel": core.log_level, "access": "none" })
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": { "domainStrategy": "IPIfNonMatch", "rules": rules },
    });
    if core.api_port != 0 {
        config["stats"] = json!({});
        config["api"] = json!({ "tag": "api", "services": ["StatsService"] });
        config["policy"] = json!({
            "system": { "statsOutboundUplink": true, "statsOutboundDownlink": true }
        });
    }
    if full_balanced {
        config["routing"]["balancers"] = json!(balancers);
        if let Some((key, v)) = full.as_ref().and_then(|p| p.observatory.clone()) {
            config[key] = v;
        }
    }
    if let Some(f) = plan.failover.as_ref().filter(|_| full.is_none()) {
        config["routing"]["balancers"] = json!(balancers);
        config["observatory"] = json!({
            "subjectSelector": ["proxy-"],
            "probeUrl": f.probe_url,
            "probeInterval": format!("{}s", f.interval_secs),
            "enableConcurrency": true,
        });
    }
    if let Some(dns) = dns {
        config["dns"] = dns;
    }
    Ok(config)
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
    fn tls_grpc_authority_and_multi_mode() {
        insta::assert_json_snapshot!(config_for(&format!(
            "vless://{UUID}@g.example.com:443?security=tls&sni=g.example.com&type=grpc&serviceName=svc&authority=cdn.example.com&mode=multi#G"
        )));
    }

    const REALITY_LINK: &str = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@de.example.com:443?flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=4GObrWHDR0TyD84iQ06z24v4YBxQ69vxeG1MCqOyFlI&sid=ab12cd34&type=tcp#DE-1";

    #[test]
    fn fragmentation_is_added_only_when_switched_on_and_only_for_tls() {
        let mut s = parse_link(REALITY_LINK).unwrap();
        let off = build(&s, &CoreConfig::default()).unwrap();
        assert!(off["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .all(|o| o["tag"] != "fragment"));
        assert!(off["outbounds"][0]["streamSettings"]
            .get("sockopt")
            .is_none());

        s.fragment = true;
        let on = build(&s, &CoreConfig::default()).unwrap();
        insta::assert_json_snapshot!("reality_fragment", on);
        assert_eq!(
            on["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"],
            "fragment"
        );

        // Plain (no TLS) connections have no ClientHello to cut.
        let mut plain = parse_link("vless://u@10.0.0.5:443?security=none#p").unwrap();
        plain.fragment = true;
        let cfg = build(&plain, &CoreConfig::default()).unwrap();
        assert!(cfg["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .all(|o| o["tag"] != "fragment"));
    }

    fn failover_plan(routing: RoutingMode) -> Plan {
        let backup = parse_link(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@ru.example.com:443?security=reality&sni=ya.ru&fp=chrome&pbk=4GObrWHDR0TyD84iQ06z24v4YBxQ69vxeG1MCqOyFlI&sid=ab&type=tcp#RU-entry",
        )
        .unwrap();
        Plan {
            routing,
            failover: Some(Failover::new(
                backup,
                None,
                "https://www.gstatic.com/generate_204".into(),
            )),
            ..Plan::proxy_default()
        }
    }

    #[test]
    fn failover_snapshots_for_both_routing_modes() {
        let s = parse_link(REALITY_LINK).unwrap();
        for (name, mode) in [
            ("exclude", RoutingMode::Exclude),
            ("include", RoutingMode::Include),
        ] {
            let cfg = build_with(&s, &CoreConfig::default(), &failover_plan(mode)).unwrap();
            insta::assert_json_snapshot!(format!("failover_{name}"), cfg);
        }
    }

    #[test]
    fn failover_has_no_plain_proxy_tag_left_in_rules() {
        let s = parse_link(REALITY_LINK).unwrap();
        let cfg = build_with(
            &s,
            &CoreConfig::default(),
            &failover_plan(RoutingMode::Exclude),
        )
        .unwrap();
        let tags: Vec<&str> = cfg["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["tag"].as_str().unwrap())
            .collect();
        assert!(tags.contains(&"proxy-primary") && tags.contains(&"proxy-backup"));
        assert!(!tags.contains(&"proxy"), "the balancer owns that name");
        for r in cfg["routing"]["rules"].as_array().unwrap() {
            assert_ne!(r["outboundTag"], "proxy", "{r}");
        }
        assert_eq!(
            cfg["routing"]["balancers"][0]["fallbackTag"],
            "proxy-backup"
        );
        assert_eq!(cfg["observatory"]["probeInterval"], "10s");
    }

    const EXTRA_JSON: &str = r#"{"scMaxEachPostBytes":"1000000","scMaxConcurrentPosts":"100","xPaddingBytes":"100-1000","noGRPCHeader":false,"sessionPlacement":"cookie","sessionKey":"sid","seqPlacement":"path","headers":{"X-A":"b"},"someFutureKey":{"n":[1,2]},"xmux":{"maxConcurrency":"16-32","hKeepAlivePeriod":0}}"#;

    fn extra_link() -> String {
        format!("vless://{UUID}@exchange.example.com:443?security=tls&type=xhttp&headerType=&path=%2Fapi%2Fsource&host=exchange.example.com&mode=packet-up&extra=%7B%22scMaxEachPostBytes%22%3A%221000000%22%2C%22scMaxConcurrentPosts%22%3A%22100%22%2C%22xPaddingBytes%22%3A%22100-1000%22%2C%22noGRPCHeader%22%3Afalse%2C%22sessionPlacement%22%3A%22cookie%22%2C%22sessionKey%22%3A%22sid%22%2C%22seqPlacement%22%3A%22path%22%2C%22headers%22%3A%7B%22X-A%22%3A%22b%22%7D%2C%22someFutureKey%22%3A%7B%22n%22%3A%5B1%2C2%5D%7D%2C%22xmux%22%3A%7B%22maxConcurrency%22%3A%2216-32%22%2C%22hKeepAlivePeriod%22%3A0%7D%7D&sni=exchange.example.com&fp=chrome&alpn=h2%2Chttp%2F1.1#x")
    }

    #[test]
    fn xhttp_extra_is_passed_whole_into_the_outbound() {
        let cfg = config_for(&extra_link());
        let x = &cfg["outbounds"][0]["streamSettings"]["xhttpSettings"];
        let want: Value = serde_json::from_str(EXTRA_JSON).unwrap();
        assert_eq!(x["extra"], want, "unknown keys must survive too");
        assert_eq!(x["mode"], "packet-up");
        assert_eq!(x["path"], "/api/source");
        assert_eq!(
            cfg["outbounds"][0]["streamSettings"]["tlsSettings"]["fingerprint"],
            "chrome"
        );
        let s = parse_link(&extra_link()).unwrap();
        assert_eq!(s.params.extra_count(), 10);
    }

    #[test]
    fn broken_extra_marks_the_server_unsupported_instead_of_dropping_it() {
        let s = parse_link(&format!(
            "vless://{UUID}@h.example.com:443?security=tls&type=xhttp&extra=%7Bnot-json#t"
        ))
        .unwrap();
        assert!(!s.is_supported());
    }

    #[test]
    fn an_automatic_fingerprint_never_replaces_the_links_fp() {
        let mut s = parse_link(&extra_link()).unwrap();
        s.fp_override = Some("firefox".into());
        s.fp_auto = true;
        assert_eq!(s.effective_fingerprint(), "chrome");
        // Without an fp in the link the automatic one applies.
        let mut s = parse_link(&format!(
            "vless://{UUID}@h.example.com:443?security=tls&sni=h.example.com#t"
        ))
        .unwrap();
        s.fp_override = Some("firefox".into());
        s.fp_auto = true;
        assert_eq!(s.effective_fingerprint(), "firefox");
    }

    #[test]
    fn fingerprint_override_replaces_the_links_fp_in_the_config() {
        let reality = format!(
            "vless://{UUID}@h.example.com:443?security=reality&sni=x.org&pbk=K&sid=ab&fp=chrome#r"
        );
        let mut server = parse_link(&reality).unwrap();
        let core = CoreConfig::default();
        let fp = |s: &Server| {
            build(s, &core).unwrap()["outbounds"][0]["streamSettings"]["realitySettings"]
                ["fingerprint"]
                .clone()
        };
        assert_eq!(fp(&server), "chrome");
        server.fp_override = Some("firefox".into());
        assert_eq!(fp(&server), "firefox");
        assert_eq!(
            server.tls.fingerprint, "chrome",
            "the link's own fp is untouched"
        );

        let tls =
            format!("vless://{UUID}@h.example.com:443?security=tls&sni=h.example.com&fp=chrome#t");
        let mut server = parse_link(&tls).unwrap();
        server.fp_override = Some("safari".into());
        let cfg = build(&server, &core).unwrap();
        assert_eq!(
            cfg["outbounds"][0]["streamSettings"]["tlsSettings"]["fingerprint"],
            "safari"
        );
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
        let server =
            parse_link(&format!("vless://{UUID}@h.example.com:443?security=tls#x")).unwrap();
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

    #[test]
    fn encryption_reaches_the_outbound_unchanged() {
        let enc = "mlkem768x25519plus.native.0rtt.45M6KAE8QF6VlzscrkIrjshB78IYPvGemYDCFrzFi14";
        let cfg = config_for(&format!(
            "vless://{UUID}@8.8.8.8:443?security=none&encryption={enc}#pq"
        ));
        let user = &cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0];
        assert_eq!(user["encryption"], enc);
    }

    // ---------------------------------------------------------------- TUN / rules

    use crate::model::rule::{builtin_presets, effective_rules, Rule, RuleKind};

    fn tun_plan(windows: bool, ipv6: bool) -> TunPlan {
        TunPlan {
            name: "elfgate0".into(),
            ipv6,
            windows,
            tunnel_dns: "1.1.1.1".into(),
            local_dns: vec!["192.168.1.1".into()],
        }
    }

    /// OS-independent on purpose (`windows = false`), so snapshots match on every CI runner.
    pub(super) fn plan_for(
        routing: RoutingMode,
        presets: &[&str],
        rules: &[Rule],
        tun: bool,
    ) -> Plan {
        let ids: Vec<String> = presets.iter().map(|s| s.to_string()).collect();
        let mut effective = effective_rules(routing, rules, &ids, &builtin_presets(), false);
        // Fixed, OS-independent data set (what Xray's bundled files contain), so the snapshots
        // do not depend on which .dat files the machine has.
        let geo =
            crate::xray::geodata::Geo::from_codes(&["CATEGORY-RU", "DISCORD"], &["RU", "PRIVATE"]);
        crate::xray::geodata::drop_missing(&mut effective, &geo);
        Plan {
            traffic: if tun {
                TrafficMode::Tun
            } else {
                TrafficMode::Proxy
            },
            routing,
            rules: effective,
            tun: tun.then(|| tun_plan(false, true)),
            vps_ip: None,
            failover: None,
            direct_ips: Vec::new(),
            direct_domains: Vec::new(),
            pin: std::collections::HashMap::new(),
        }
    }

    fn server() -> Server {
        parse_link(&format!(
            "vless://{UUID}@de.example.com:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=4GObrWHDR0TyD84iQ06z24v4YBxQ69vxeG1MCqOyFlI&sid=ab12cd34&flow=xtls-rprx-vision#DE"
        ))
        .unwrap()
    }

    #[test]
    fn every_preset_in_both_routing_modes_snapshot() {
        for preset in builtin_presets() {
            for (mode, tag) in [
                (RoutingMode::Exclude, "exclude"),
                (RoutingMode::Include, "include"),
            ] {
                let plan = plan_for(mode, &[preset.id.as_str()], &[], true);
                let cfg = build_with(&server(), &CoreConfig::default(), &plan).unwrap();
                insta::assert_json_snapshot!(format!("preset_{}_{tag}", preset.id), cfg);
            }
        }
    }

    #[test]
    fn plain_proxy_plan_equals_the_classic_config() {
        let a = build(&server(), &CoreConfig::default()).unwrap();
        let plan = Plan {
            tun: None,
            ..plan_for(RoutingMode::Exclude, &["local-direct"], &[], false)
        };
        let b = build_with(&server(), &CoreConfig::default(), &plan).unwrap();
        assert_eq!(a, b);
        assert!(a["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["protocol"] != "tun"));
    }

    #[test]
    fn tun_inbound_has_routes_interface_binding_and_ipv6_switch() {
        let mut plan = plan_for(RoutingMode::Exclude, &["local-direct"], &[], true);
        let cfg = build_with(&server(), &CoreConfig::default(), &plan).unwrap();
        let tun = cfg["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["protocol"] == "tun")
            .unwrap();
        assert_eq!(tun["settings"]["name"], "elfgate0");
        assert_eq!(tun["settings"]["autoOutboundsInterface"], "auto");
        assert_eq!(
            tun["settings"]["autoSystemRoutingTable"],
            json!(["0.0.0.0/0", "::/0"])
        );
        assert!(
            tun["settings"].get("autoSystemWfpBlockLeak").is_none(),
            "Windows-only"
        );
        // The local socks inbound stays: the health check goes through it.
        assert!(cfg["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["tag"] == "socks-in"));

        plan.tun = Some(tun_plan(false, false));
        let cfg = build_with(&server(), &CoreConfig::default(), &plan).unwrap();
        let tun = cfg["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["protocol"] == "tun")
            .unwrap();
        assert_eq!(
            tun["settings"]["autoSystemRoutingTable"],
            json!(["0.0.0.0/0"])
        );
        assert_eq!(tun["settings"]["gateway"].as_array().unwrap().len(), 1);

        plan.tun = Some(tun_plan(true, true));
        let cfg = build_with(&server(), &CoreConfig::default(), &plan).unwrap();
        let tun = cfg["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["protocol"] == "tun")
            .unwrap();
        assert_eq!(
            tun["settings"]["autoSystemWfpBlockLeak"],
            json!(["misconfigtun"])
        );
        assert_eq!(tun["settings"]["desc"], "elf-gate");
    }

    /// A `process` rule that is not the built-in "elf-gate itself goes direct" one.
    fn user_process_rule(r: &Value) -> bool {
        r.get("process")
            .and_then(Value::as_array)
            .is_some_and(|p| !p.contains(&json!("elf-gate")))
    }

    #[test]
    fn servers_and_subscription_hosts_never_enter_the_tunnel() {
        for mode in [RoutingMode::Exclude, RoutingMode::Include] {
            let mut plan = plan_for(mode, &["local-direct"], &[], true);
            plan.direct_ips = vec!["212.147.241.154".into(), "2001:db8::1".into()];
            plan.direct_domains = vec!["full:vpn.example.com".into()];
            let cfg = build_with(&server(), &CoreConfig::default(), &plan).unwrap();
            let rules = cfg["routing"]["rules"].as_array().unwrap();
            let ip_rule = rules
                .iter()
                .position(|r| r["ip"] == json!(["212.147.241.154", "2001:db8::1"]))
                .expect("direct ip rule");
            assert_eq!(rules[ip_rule]["outboundTag"], "direct");
            let first_user = rules
                .iter()
                .position(|r| r.get("process").is_some())
                .unwrap_or(rules.len());
            assert!(ip_rule < first_user, "before process and other user rules");
            assert!(rules
                .iter()
                .any(|r| r["domain"] == json!(["full:vpn.example.com"])
                    && r["outboundTag"] == "direct"));
        }
        // Plain proxy mode has no tunnel to loop through.
        let mut plan = plan_for(RoutingMode::Exclude, &[], &[], false);
        plan.direct_ips = vec!["1.2.3.4".into()];
        let cfg = build_with(&server(), &CoreConfig::default(), &plan).unwrap();
        assert!(cfg["routing"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["ip"] != json!(["1.2.3.4"])));
    }

    #[test]
    fn elf_gates_own_traffic_stays_outside_the_tunnel_in_every_mode() {
        for mode in [RoutingMode::Exclude, RoutingMode::Include] {
            let cfg = build_with(
                &server(),
                &CoreConfig::default(),
                &plan_for(mode, &["local-direct"], &[], true),
            )
            .unwrap();
            let own = cfg["routing"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["process"] == json!(["elf-gate", "elf-gated"]))
                .expect("self rule");
            assert_eq!(own["outboundTag"], "direct");
        }
        let plain = build(&server(), &CoreConfig::default()).unwrap();
        assert!(plain["routing"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r.get("process").is_none()));
    }

    #[test]
    fn process_rules_apply_in_tun_mode_only() {
        let rules = [Rule::new(RuleKind::Process, "Discord")];
        let has_process_rule = |tun: bool, mode| {
            let cfg = build_with(
                &server(),
                &CoreConfig::default(),
                &plan_for(mode, &["local-direct"], &rules, tun),
            )
            .unwrap();
            cfg["routing"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(user_process_rule)
        };
        assert!(has_process_rule(true, RoutingMode::Include));
        assert!(has_process_rule(true, RoutingMode::Exclude));
        assert!(
            !has_process_rule(false, RoutingMode::Include),
            "inactive in proxy mode"
        );
    }

    #[test]
    fn include_mode_sends_listed_things_to_the_vpn_and_the_rest_direct() {
        let rules = [
            Rule::new(RuleKind::Process, "Discord"),
            Rule::new(RuleKind::Domain, "discord.com"),
        ];
        let cfg = build_with(
            &server(),
            &CoreConfig::default(),
            &plan_for(RoutingMode::Include, &["local-direct"], &rules, true),
        )
        .unwrap();
        let r = cfg["routing"]["rules"].as_array().unwrap();
        let process = r.iter().find(|r| user_process_rule(r)).unwrap();
        assert_eq!(process["outboundTag"], "proxy");
        let last = r.last().unwrap();
        assert_eq!(last["outboundTag"], "direct");
        assert_eq!(last["network"], "tcp,udp");
        // Local network is direct before anything else matches.
        let first_non_dns = r.iter().find(|r| r.get("ip").is_some()).unwrap();
        assert_eq!(first_non_dns["ip"], json!(["geoip:private"]));
    }

    #[test]
    fn exclude_mode_sends_listed_things_direct_and_has_no_catch_all() {
        let rules = [Rule::new(RuleKind::Process, "steam")];
        let cfg = build_with(
            &server(),
            &CoreConfig::default(),
            &plan_for(RoutingMode::Exclude, &["local-direct"], &rules, true),
        )
        .unwrap();
        let r = cfg["routing"]["rules"].as_array().unwrap();
        assert_eq!(
            r.iter().find(|r| user_process_rule(r)).unwrap()["outboundTag"],
            "direct"
        );
        assert!(r
            .iter()
            .filter(|r| r["outboundTag"] != "dns-out")
            .all(|r| r.get("network") != Some(&json!("tcp,udp"))));
        assert_eq!(
            cfg["outbounds"][0]["tag"], "proxy",
            "the first outbound is the default: the VPN"
        );
    }

    #[test]
    fn dns_servers_split_by_listed_domains_and_local_resolver() {
        let with = |mode, rules: &[Rule]| {
            build_with(
                &server(),
                &CoreConfig::default(),
                &plan_for(mode, &["local-direct"], rules, true),
            )
            .unwrap()
        };
        // No listed domains: everything resolves through the tunnel.
        let cfg = with(RoutingMode::Include, &[Rule::new(RuleKind::Process, "x")]);
        let servers = cfg["dns"]["servers"].as_array().unwrap();
        assert!(servers.iter().all(|s| s.get("domains").is_none()));
        assert!(servers
            .iter()
            .all(|s| s["address"].as_str().unwrap().starts_with("https://")));

        let cfg = with(
            RoutingMode::Include,
            &[Rule::new(RuleKind::Domain, "discord.com")],
        );
        let servers = cfg["dns"]["servers"].as_array().unwrap();
        assert_eq!(servers[0]["tag"], "dns-tunnel");
        assert_eq!(servers[0]["domains"], json!(["domain:discord.com"]));
        assert_eq!(servers[0]["skipFallback"], true);
        let local = servers.iter().find(|s| s["tag"] == "dns-local-0").unwrap();
        assert_eq!(
            local["address"], "192.168.1.1",
            "unlisted names resolve locally"
        );
        assert!(local.get("domains").is_none());
        assert!(cfg["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["tag"] == "dns-out"));
        assert_eq!(cfg["routing"]["rules"][1]["outboundTag"], "dns-out");

        let cfg = with(
            RoutingMode::Exclude,
            &[Rule::new(RuleKind::Domain, "example.ru")],
        );
        let servers = cfg["dns"]["servers"].as_array().unwrap();
        assert_eq!(
            servers[0]["tag"], "dns-local-0",
            "exclude: listed names resolve locally"
        );
        assert_eq!(servers[0]["domains"], json!(["domain:example.ru"]));
        assert_eq!(servers[1]["tag"], "dns-tunnel");
        assert!(
            servers[1].get("skipFallback").is_none(),
            "the default server must stay usable for unlisted names"
        );

        let mut plan = plan_for(
            RoutingMode::Include,
            &["local-direct"],
            &[Rule::new(RuleKind::Domain, "discord.com")],
            true,
        );
        plan.tun.as_mut().unwrap().local_dns.clear();
        let cfg = build_with(&server(), &CoreConfig::default(), &plan).unwrap();
        let servers = cfg["dns"]["servers"].as_array().unwrap();
        assert!(
            servers.iter().all(|s| s.get("domains").is_none()),
            "no local resolver known: the tunnel resolves everything"
        );
    }

    fn rules_of(cfg: &Value) -> Vec<Value> {
        cfg["routing"]["rules"].as_array().unwrap().clone()
    }

    #[test]
    fn tun_hijacks_port_53_above_private_direct_and_user_rules() {
        for mode in [RoutingMode::Exclude, RoutingMode::Include] {
            let cfg = build_with(
                &server(),
                &CoreConfig::default(),
                &plan_for(
                    mode,
                    &["local-direct"],
                    &[Rule::new(RuleKind::Process, "steam")],
                    true,
                ),
            )
            .unwrap();
            let r = rules_of(&cfg);
            let dns = r
                .iter()
                .position(|r| {
                    r["outboundTag"] == "dns-out"
                        && r["port"] == "53"
                        && r["network"] == "tcp,udp"
                        && r["inboundTag"] == json!(["tun-in"])
                        && r.get("ip").is_none()
                })
                .expect("a port 53 -> dns-out rule for any destination");
            let private = r
                .iter()
                .position(|r| r["ip"] == json!(["geoip:private"]))
                .expect("geoip:private -> direct is present in the default plan");
            let user = r.iter().position(user_process_rule).unwrap();
            assert!(dns < private, "{mode:?}");
            assert!(dns < user, "{mode:?}");
            assert!(
                r[..dns].iter().all(|r| r["outboundTag"] == "api"),
                "only the internal api rule may precede the hijack"
            );
        }
    }

    #[test]
    fn tunnel_dns_uses_doh_with_a_fallback_never_plain_udp() {
        let cfg = build_with(
            &server(),
            &CoreConfig::default(),
            &plan_for(RoutingMode::Exclude, &["local-direct"], &[], true),
        )
        .unwrap();
        let servers = cfg["dns"]["servers"].as_array().unwrap();
        assert_eq!(servers[0]["address"], "https://1.1.1.1/dns-query");
        assert_eq!(servers[1]["address"], "https://8.8.8.8/dns-query");
        assert_eq!(servers[0]["tag"], "dns-tunnel");
        assert_eq!(servers[1]["tag"], "dns-tunnel-1");
        let r = rules_of(&cfg);
        assert!(r
            .iter()
            .any(|r| r["inboundTag"] == json!(["dns-tunnel", "dns-tunnel-1"])
                && r["outboundTag"] == "proxy"));

        // An unknown plain resolver address is asked over TCP.
        let mut plan = plan_for(RoutingMode::Exclude, &["local-direct"], &[], true);
        plan.tun.as_mut().unwrap().tunnel_dns = "9.9.9.10".into();
        let cfg = build_with(&server(), &CoreConfig::default(), &plan).unwrap();
        assert_eq!(cfg["dns"]["servers"][0]["address"], "tcp://9.9.9.10");
    }

    #[test]
    fn pre_resolved_vps_ip_keeps_the_domain_as_sni_and_host() {
        let mut plan = plan_for(RoutingMode::Exclude, &["local-direct"], &[], true);
        plan.vps_ip = Some("203.0.113.9".into());
        let tls = parse_link(&format!(
            "vless://{UUID}@vpn.example.com:443?security=tls&type=ws&path=%2Fws#t"
        ))
        .unwrap();
        let cfg = build_with(&tls, &CoreConfig::default(), &plan).unwrap();
        let out = &cfg["outbounds"][0];
        assert_eq!(out["settings"]["vnext"][0]["address"], "203.0.113.9");
        assert_eq!(
            out["streamSettings"]["tlsSettings"]["serverName"],
            "vpn.example.com"
        );
        assert_eq!(
            out["streamSettings"]["wsSettings"]["host"],
            "vpn.example.com"
        );

        // An explicit sni in the link wins over the fallback.
        let reality = format!("vless://{UUID}@vpn.example.com:443?security=reality&sni=www.microsoft.com&pbk=K&sid=ab#r");
        let cfg = build_with(
            &parse_link(&reality).unwrap(),
            &CoreConfig::default(),
            &plan,
        )
        .unwrap();
        assert_eq!(
            cfg["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"],
            "www.microsoft.com"
        );
        // Without an override nothing changes.
        let plain = build(&tls, &CoreConfig::default()).unwrap();
        assert_eq!(
            plain["outbounds"][0]["settings"]["vnext"][0]["address"],
            "vpn.example.com"
        );
    }

    #[test]
    fn quic_block_preset_adds_a_udp_443_block_rule() {
        let cfg = build_with(
            &server(),
            &CoreConfig::default(),
            &plan_for(RoutingMode::Exclude, &["block-quic"], &[], true),
        )
        .unwrap();
        let r = cfg["routing"]["rules"].as_array().unwrap();
        assert!(r
            .iter()
            .any(|r| r["network"] == "udp" && r["port"] == "443" && r["outboundTag"] == "block"));
    }
}
