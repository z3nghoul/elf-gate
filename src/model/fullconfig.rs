//! Servers that come as complete Xray configs (JSON subscriptions, Remnawave and similar).
//!
//! A provider's entry is a whole config: several outbounds that form a chain (one outbound
//! dials through another via `sockopt.dialerProxy` or `proxySettings.tag`), sometimes a balancer
//! over several of them. Taking one outbound out of it would break the chain, so the whole set
//! is kept and carried over as it is (nothing inside an outbound is rewritten except the tags
//! that point at other outbounds). Only the names change, so they cannot clash with ours.

use super::server::{Security, Server, Transport};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Our own tag for the provider's entry point; our routing rules already point at it.
pub const MAIN_TAG: &str = "proxy";
/// Prefix of every other provider outbound.
pub const PREFIX: &str = "pv-";
/// Prefix of a link that holds one provider entry (JSON) instead of a share link.
pub const LINK_PREFIX: &str = "xrayjson:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    Outbound(String),
    Balancer(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullConfig {
    /// The provider's outbounds that matter (the entry point and everything it reaches).
    /// Empty in the copy the interface sees.
    pub outbounds: Vec<Value>,
    /// Provider balancers the entry point needs (with their original tags).
    pub balancers: Vec<Value>,
    /// `observatory` / `burstObservatory` of the entry, as `(key, value)`.
    pub observatory: Option<(String, Value)>,
    pub main: Target,
    /// How many proxy outbounds the chain has.
    pub hops: usize,
}

/// What the build needs: outbounds and balancers with the new names.
#[derive(Debug, Clone, Default)]
pub struct Renamed {
    pub outbounds: Vec<Value>,
    pub balancers: Vec<Value>,
    pub observatory: Option<(String, Value)>,
    /// The entry point is a balancer named [`MAIN_TAG`].
    pub balanced: bool,
}

const ZERO_UUID: &str = "00000000-0000-0000-0000-000000000000";

fn s(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

fn tag_of(ob: &Value) -> Option<String> {
    s(ob, "tag")
}

/// The outbound this one dials through, if any.
fn dialer_of(ob: &Value) -> Option<String> {
    ob.pointer("/streamSettings/sockopt/dialerProxy")
        .and_then(Value::as_str)
        .or_else(|| ob.pointer("/proxySettings/tag").and_then(Value::as_str))
        .map(str::to_string)
        .filter(|t| !t.is_empty())
}

fn is_proxy(ob: &Value) -> bool {
    matches!(
        ob.get("protocol").and_then(Value::as_str),
        Some(
            "vless"
                | "vmess"
                | "trojan"
                | "shadowsocks"
                | "hysteria"
                | "hysteria2"
                | "wireguard"
                | "socks"
                | "http"
        )
    )
}

/// `(address, port, id)` of a proxy outbound, in the `vnext` form and in the flat one.
fn endpoint(ob: &Value) -> Option<(String, u16, String)> {
    let st = ob.get("settings")?;
    let node = st
        .pointer("/vnext/0")
        .or_else(|| st.pointer("/servers/0"))
        .unwrap_or(st);
    let address = s(node, "address")?;
    let port = node.get("port").and_then(Value::as_u64)? as u16;
    let id = node
        .pointer("/users/0/id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| s(node, "id"))
        .or_else(|| s(node, "password"))
        .unwrap_or_default();
    Some((address, port, id))
}

/// Placeholder entries: zero UUID, address 0.0.0.0, port 0 or 1.
pub fn is_stub(address: &str, port: u16, id: &str) -> bool {
    id == ZERO_UUID || address == "0.0.0.0" || address == "::" || port <= 1
}

/// The default destination of the provider's routing: the last rule that has no condition
/// besides the network, else the outbound tagged `proxy`, else the first proxy outbound.
fn default_target(entry: &Value, outbounds: &[Value]) -> Option<Target> {
    let mut found = None;
    if let Some(rules) = entry.pointer("/routing/rules").and_then(Value::as_array) {
        for r in rules {
            let Some(obj) = r.as_object() else { continue };
            let plain = obj.keys().all(|k| {
                matches!(
                    k.as_str(),
                    "type" | "network" | "outboundTag" | "balancerTag" | "ruleTag"
                )
            });
            if !plain {
                continue;
            }
            if let Some(t) = obj.get("balancerTag").and_then(Value::as_str) {
                found = Some(Target::Balancer(t.to_string()));
            } else if let Some(t) = obj.get("outboundTag").and_then(Value::as_str) {
                found = Some(Target::Outbound(t.to_string()));
            }
        }
    }
    let usable = |t: &Target| match t {
        Target::Balancer(_) => true,
        Target::Outbound(tag) => outbounds
            .iter()
            .any(|o| tag_of(o).as_deref() == Some(tag) && is_proxy(o)),
    };
    found
        .filter(usable)
        .or_else(|| {
            outbounds
                .iter()
                .find(|o| tag_of(o).as_deref() == Some("proxy") && is_proxy(o))
                .map(|_| Target::Outbound("proxy".into()))
        })
        .or_else(|| {
            outbounds
                .iter()
                .find(|o| is_proxy(o))
                .map(|o| Target::Outbound(tag_of(o).unwrap_or_default()))
        })
}

fn transport_of(ob: &Value) -> Transport {
    match ob
        .pointer("/streamSettings/network")
        .and_then(Value::as_str)
    {
        Some("xhttp" | "splithttp") => Transport::Xhttp,
        Some("grpc") => Transport::Grpc,
        Some("ws") => Transport::Ws,
        _ => Transport::Tcp,
    }
}

fn security_of(ob: &Value) -> Security {
    match ob
        .pointer("/streamSettings/security")
        .and_then(Value::as_str)
    {
        Some("reality") => Security::Reality,
        Some("tls") => Security::Tls,
        _ => Security::None,
    }
}

impl FullConfig {
    fn by_tag<'a>(&'a self, tag: &str) -> Option<&'a Value> {
        self.outbounds
            .iter()
            .find(|o| tag_of(o).as_deref() == Some(tag))
    }

    /// Outbounds the entry point starts with: the outbound itself, or what the balancer selects.
    fn roots(&self) -> Vec<String> {
        match &self.main {
            Target::Outbound(t) => vec![t.clone()],
            Target::Balancer(t) => {
                let selectors: Vec<String> = self
                    .balancers
                    .iter()
                    .find(|b| tag_of(b).as_deref() == Some(t))
                    .and_then(|b| b.get("selector").and_then(Value::as_array).cloned())
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect();
                self.outbounds
                    .iter()
                    .filter_map(tag_of)
                    .filter(|tag| selectors.iter().any(|sel| tag.starts_with(sel.as_str())))
                    .collect()
            }
        }
    }

    /// The outbound the machine really connects to first (the end of the dialer chain of the
    /// first root): what a TCP ping, the routing-loop protection and the address list need.
    pub fn entry_hop(&self) -> Option<(String, u16)> {
        let mut tag = self.roots().into_iter().next()?;
        for _ in 0..16 {
            let ob = self.by_tag(&tag)?;
            match dialer_of(ob) {
                Some(next) if self.by_tag(&next).is_some_and(is_proxy) => tag = next,
                _ => return endpoint(ob).map(|(a, p, _)| (a, p)),
            }
        }
        None
    }

    /// Every host of the chain (all hops): none of them may be reached through the tunnel.
    pub fn hosts(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for ob in &self.outbounds {
            if let Some((a, _, _)) = endpoint(ob) {
                if !out.contains(&a) {
                    out.push(a);
                }
            }
        }
        out
    }

    /// The outbounds and balancers with new names: the entry point is [`MAIN_TAG`] (an
    /// outbound) or a balancer of that name; everything else gets [`PREFIX`], and the
    /// references between them follow. `pin` maps host names to addresses (TUN resolves them
    /// before the tunnel exists); the name stays as the TLS server name when none is set.
    pub fn renamed(&self, pin: &HashMap<String, String>) -> Renamed {
        let balanced = matches!(self.main, Target::Balancer(_));
        let new_tag = |old: &str| -> String {
            match &self.main {
                Target::Outbound(m) if m == old => MAIN_TAG.to_string(),
                _ => format!("{PREFIX}{old}"),
            }
        };
        let mut outbounds = Vec::new();
        for ob in &self.outbounds {
            let mut ob = ob.clone();
            if let Some(old) = tag_of(&ob) {
                ob["tag"] = Value::String(new_tag(&old));
            }
            if let Some(d) = dialer_of(&ob) {
                let n = new_tag(&d);
                if ob.pointer("/streamSettings/sockopt/dialerProxy").is_some() {
                    ob["streamSettings"]["sockopt"]["dialerProxy"] = Value::String(n.clone());
                }
                if ob.pointer("/proxySettings/tag").is_some() {
                    // Xray 26 removed `proxySettings`: it is the same thing as
                    // `streamSettings.sockopt.dialerProxy`, the only change made inside an outbound.
                    if let Some(obj) = ob.as_object_mut() {
                        obj.remove("proxySettings");
                    }
                    if !ob.get("streamSettings").is_some_and(Value::is_object) {
                        ob["streamSettings"] = Value::Object(Default::default());
                    }
                    if !ob["streamSettings"]
                        .get("sockopt")
                        .is_some_and(Value::is_object)
                    {
                        ob["streamSettings"]["sockopt"] = Value::Object(Default::default());
                    }
                    ob["streamSettings"]["sockopt"]["dialerProxy"] = Value::String(n);
                }
            }
            pin_addresses(&mut ob, pin);
            outbounds.push(ob);
        }
        // The entry point first: Xray's default outbound is the first one.
        if let Target::Outbound(m) = &self.main {
            if let Some(i) = outbounds
                .iter()
                .position(|o| tag_of(o).as_deref() == Some(MAIN_TAG))
            {
                let _ = m;
                let main = outbounds.remove(i);
                outbounds.insert(0, main);
            }
        }
        let mut balancers = Vec::new();
        for b in &self.balancers {
            let mut b = b.clone();
            if let Target::Balancer(m) = &self.main {
                if tag_of(&b).as_deref() == Some(m) {
                    b["tag"] = Value::String(MAIN_TAG.into());
                }
            }
            if let Some(sel) = b.get("selector").and_then(Value::as_array) {
                b["selector"] = Value::Array(
                    sel.iter()
                        .filter_map(Value::as_str)
                        .map(|t| Value::String(format!("{PREFIX}{t}")))
                        .collect(),
                );
            }
            if let Some(f) = s(&b, "fallbackTag") {
                b["fallbackTag"] = Value::String(format!("{PREFIX}{f}"));
            }
            balancers.push(b);
        }
        let observatory = self.observatory.clone().map(|(key, mut v)| {
            if let Some(sel) = v.get("subjectSelector").and_then(Value::as_array) {
                v["subjectSelector"] = Value::Array(
                    sel.iter()
                        .filter_map(Value::as_str)
                        .map(|t| Value::String(format!("{PREFIX}{t}")))
                        .collect(),
                );
            }
            (key, v)
        });
        Renamed {
            outbounds,
            balancers,
            observatory,
            balanced,
        }
    }
}

/// Replaces a host name by its pre-resolved address in a proxy outbound; the name stays as the
/// server name for TLS/Reality when the outbound has none.
fn pin_addresses(ob: &mut Value, pin: &HashMap<String, String>) {
    if pin.is_empty() || !is_proxy(ob) {
        return;
    }
    let Some((host, _, _)) = endpoint(ob) else {
        return;
    };
    let Some(ip) = pin.get(&host) else { return };
    for ptr in ["/settings/vnext/0", "/settings/servers/0", "/settings"] {
        if ob.pointer(ptr).and_then(|n| n.get("address")).is_some() {
            ob.pointer_mut(ptr).unwrap()["address"] = Value::String(ip.clone());
            break;
        }
    }
    for sec in ["realitySettings", "tlsSettings"] {
        let key = format!("/streamSettings/{sec}");
        if let Some(node) = ob.pointer_mut(&key) {
            if node
                .get("serverName")
                .and_then(Value::as_str)
                .unwrap_or("")
                .is_empty()
            {
                node["serverName"] = Value::String(host.clone());
            }
        }
    }
}

fn cache_link(entry: &Value) -> String {
    format!("{LINK_PREFIX}{entry}")
}

/// One provider entry -> a server. Entries that are not a usable server (separators, notices,
/// placeholders) become information-only rows.
pub fn parse_entry(entry: &Value) -> Result<Server, String> {
    let name = s(entry, "remarks").unwrap_or_else(|| "Xray config".into());
    let link = cache_link(entry);
    let outbounds: Vec<Value> = entry
        .get("outbounds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let proxies: Vec<&Value> = outbounds.iter().filter(|o| is_proxy(o)).collect();
    let endpoints: Vec<(String, u16, String)> =
        proxies.iter().filter_map(|o| endpoint(o)).collect();
    if proxies.is_empty() || endpoints.is_empty() {
        return Ok(Server::info_only(
            &link,
            name,
            "запись без сервера (заголовок или сообщение провайдера)",
        ));
    }
    if endpoints.iter().all(|(a, p, id)| is_stub(a, *p, id)) {
        return Ok(Server::info_only(
            &link,
            name,
            "заглушка провайдера (нулевой адрес): включите HWID или смените User-Agent",
        ));
    }
    let Some(main) = default_target(entry, &outbounds) else {
        return Err(format!("«{name}»: не найден основной outbound"));
    };
    let balancers_all: Vec<Value> = entry
        .pointer("/routing/balancers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let balancers: Vec<Value> = match &main {
        Target::Balancer(t) => balancers_all
            .into_iter()
            .filter(|b| tag_of(b).as_deref() == Some(t))
            .collect(),
        Target::Outbound(_) => Vec::new(),
    };
    let observatory = ["observatory", "burstObservatory"]
        .iter()
        .find_map(|k| entry.get(*k).map(|v| (k.to_string(), v.clone())))
        .filter(|_| !balancers.is_empty());

    // Keep the entry point and everything it reaches (the chain), drop the rest.
    let mut full = FullConfig {
        outbounds: outbounds.clone(),
        balancers,
        observatory,
        main,
        hops: 0,
    };
    let mut keep: HashSet<String> = HashSet::new();
    let mut stack = full.roots();
    while let Some(tag) = stack.pop() {
        if !keep.insert(tag.clone()) {
            continue;
        }
        if let Some(d) = full.by_tag(&tag).and_then(dialer_of) {
            stack.push(d);
        }
    }
    if keep.is_empty() {
        return Err(format!(
            "«{name}»: основной outbound не найден среди outbounds"
        ));
    }
    full.outbounds
        .retain(|o| tag_of(o).is_some_and(|t| keep.contains(&t)));
    full.hops = full.outbounds.iter().filter(|o| is_proxy(o)).count();
    let (address, port) = full
        .entry_hop()
        .ok_or_else(|| format!("«{name}»: не удалось определить адрес первого узла"))?;
    let main_ob = full
        .roots()
        .into_iter()
        .next()
        .and_then(|t| full.by_tag(&t).cloned());
    let mut server = Server::info_only(&link, name, "");
    server.unsupported = None;
    server.info_only = false;
    server.address = address;
    server.port = port;
    if let Some(ob) = main_ob {
        server.security = security_of(&ob);
        server.transport = transport_of(&ob);
        server.flow = ob
            .pointer("/settings/vnext/0/users/0/flow")
            .or_else(|| ob.pointer("/settings/flow"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        server.tls.sni = ob
            .pointer("/streamSettings/realitySettings/serverName")
            .or_else(|| ob.pointer("/streamSettings/tlsSettings/serverName"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
    }
    server.full = Some(full);
    Ok(server)
}

#[cfg(test)]
pub(crate) mod tests;
