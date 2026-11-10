use serde::{Deserialize, Serialize};

/// Role in the "primary + backup" scheme (stage 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerRole {
    Primary,
    Backup,
}

impl ServerRole {
    pub fn label(self) -> String {
        match self {
            ServerRole::Primary => crate::t!("role.primary"),
            ServerRole::Backup => crate::t!("role.backup"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Security {
    None,
    Tls,
    Reality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport {
    Tcp,
    Xhttp,
    Grpc,
    Ws,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ping {
    Unknown,
    Pending,
    Ms(u32),
    Timeout,
    Error,
}

/// TLS / Reality parameters from the link query.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsParams {
    pub sni: String,
    /// uTLS fingerprint (`fp`).
    pub fingerprint: String,
    pub alpn: Vec<String>,
    /// Reality public key (`pbk`).
    pub public_key: String,
    /// Reality short id (`sid`).
    pub short_id: String,
    /// Reality spider path (`spx`).
    pub spider_x: String,
    pub allow_insecure: bool,
}

/// Transport-specific parameters from the link query.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportParams {
    pub path: String,
    pub host: String,
    /// xhttp `mode`.
    pub mode: String,
    /// grpc `serviceName`.
    pub service_name: String,
    /// grpc `authority` (the HTTP/2 `:authority` header).
    pub authority: String,
}

/// uTLS fingerprints offered in the UI. `chrome` is Xray's default for Reality, but some
/// providers' DPI breaks its large post-quantum ClientHello; `firefox` often works there.
pub const FINGERPRINTS: &[&str] = &["chrome", "firefox", "safari", "ios", "edge", "qq", "random"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Server {
    /// Runtime id, assigned by the application (not persisted).
    pub id: u64,
    pub name: String,
    /// Host without IPv6 brackets.
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub flow: String,
    /// VLESS `encryption` from the link, passed to the outbound unchanged (`none` by default).
    pub encryption: String,
    pub security: Security,
    pub transport: Transport,
    pub tls: TlsParams,
    pub params: TransportParams,
    /// The original link, exactly as the user supplied it.
    pub link: String,
    /// Per-server fingerprint chosen in the UI (kept in `config.toml`). The `fp` from the
    /// link stays untouched in `tls.fingerprint`.
    pub fp_override: Option<String>,
    /// The override was found by the automatic search.
    pub fp_auto: bool,
    /// Split the TLS ClientHello (Xray `fragment`), chosen in the UI. Off by default.
    pub fragment: bool,
    pub role: Option<ServerRole>,
    /// `Some(reason)` when the server was imported but cannot be used yet.
    pub unsupported: Option<String>,
    pub ping: Ping,
    /// Unix time of the last measurement (`None` = never).
    #[serde(default)]
    pub ping_at: Option<i64>,
    /// What the number measures.
    #[serde(default)]
    pub ping_kind: PingKind,
    /// The server is a complete provider config (a chain of outbounds), not a share link.
    #[serde(default)]
    pub full: Option<super::fullconfig::FullConfig>,
    /// A row that only informs (a section title, a notice, a placeholder): not a server.
    #[serde(default)]
    pub info_only: bool,
    /// The user removed it from its subscription (see `[[hidden]]`).
    #[serde(default)]
    pub hidden: bool,
}

impl Server {
    /// A row the provider put into the list to say something.
    pub fn info_only(link: &str, name: String, note: &str) -> Self {
        let mut s = Self::unsupported(link, name, note.to_string());
        s.info_only = true;
        s
    }

    /// Every host name this server connects to (all hops of a chain).
    pub fn all_hosts(&self) -> Vec<String> {
        match &self.full {
            Some(f) => f.hosts(),
            None if self.address.is_empty() => Vec::new(),
            None => vec![self.address.clone()],
        }
    }

    /// A placeholder for links we recognise but do not support (vmess, trojan, ...).
    pub fn unsupported(link: &str, name: String, reason: String) -> Self {
        Self {
            id: 0,
            name,
            address: String::new(),
            port: 0,
            uuid: String::new(),
            flow: String::new(),
            encryption: "none".into(),
            security: Security::None,
            transport: Transport::Tcp,
            tls: TlsParams::default(),
            params: TransportParams::default(),
            link: link.to_string(),
            fp_override: None,
            fp_auto: false,
            fragment: false,
            role: None,
            unsupported: Some(reason),
            ping: Ping::Unknown,
            ping_at: None,
            ping_kind: PingKind::Tcp,
            full: None,
            info_only: false,
            hidden: false,
        }
    }

    /// The fingerprint that goes into the config: the UI override, else the link's `fp`.
    pub fn effective_fingerprint(&self) -> &str {
        self.fp_override.as_deref().unwrap_or(&self.tls.fingerprint)
    }

    pub fn is_supported(&self) -> bool {
        self.unsupported.is_none()
    }

    /// Explanation when the transport still works but Xray marks it deprecated.
    /// This is separate from `unsupported` (incompatibility): such servers stay usable.
    pub fn deprecated_transport(&self) -> Option<String> {
        if !self.is_supported() {
            return None;
        }
        match self.transport {
            Transport::Ws => Some(crate::t!("model.deprecated_ws")),
            Transport::Grpc => Some(crate::t!("model.deprecated_grpc")),
            Transport::Tcp | Transport::Xhttp => None,
        }
    }

    /// The copy the UI may see: the secrets that identify or unlock the server (user id, link,
    /// Reality keys) are removed, everything the screens show stays.
    pub fn redacted(&self) -> Server {
        let mut s = self.clone();
        s.uuid.clear();
        s.link.clear();
        s.tls.public_key.clear();
        s.tls.short_id.clear();
        if let Some(f) = &mut s.full {
            // The chain holds keys: the interface only needs to know that there is one.
            f.outbounds.clear();
            f.balancers.clear();
            f.observatory = None;
        }
        s
    }

    /// `host:port`, with IPv6 addresses in brackets.
    pub fn host_port(&self) -> String {
        if self.address.contains(':') {
            format!("[{}]:{}", self.address, self.port)
        } else {
            format!("{}:{}", self.address, self.port)
        }
    }
}

impl Security {
    pub fn label(self) -> &'static str {
        match self {
            Security::None => "none",
            Security::Tls => "TLS",
            Security::Reality => "Reality",
        }
    }
}

impl Transport {
    pub fn label(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Xhttp => "xhttp",
            Transport::Grpc => "grpc",
            Transport::Ws => "ws",
        }
    }
}

/// What a ping value measures: they are different things and must not be mixed up.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PingKind {
    /// Time to open a TCP connection to the server (the way there only).
    #[default]
    Tcp,
    /// A request through the working tunnel (the way there and the way out).
    Tunnel,
}

impl PingKind {
    pub fn short(self) -> &'static str {
        match self {
            PingKind::Tcp => "tcp",
            PingKind::Tunnel => "vpn",
        }
    }
    pub fn long(self) -> String {
        match self {
            PingKind::Tcp => crate::t!("pingkind.tcp"),
            PingKind::Tunnel => crate::t!("pingkind.tunnel"),
        }
    }
}

/// `42 ms, 30 s ago`: the age tells that the number is alive.
pub fn ping_label_with_age(ping: Ping, at: Option<i64>, now: i64) -> String {
    let base = ping.label();
    let Some(at) = at.filter(|_| !matches!(ping, Ping::Unknown | Ping::Pending)) else {
        return base;
    };
    let age = (now - at).max(0);
    let ago = if age < 90 {
        crate::t!("ping.unit_s", n = age)
    } else if age < 5400 {
        crate::t!("ping.unit_min", n = age / 60)
    } else {
        crate::t!("ping.unit_h", n = age / 3600)
    };
    crate::t!("ping.age", base = base, ago = ago)
}

impl Ping {
    pub fn label(self) -> String {
        match self {
            Ping::Unknown => "-".into(),
            Ping::Pending => "...".into(),
            Ping::Ms(ms) => format!("{ms} ms"),
            Ping::Timeout => "timeout".into(),
            Ping::Error => "error".into(),
        }
    }

    /// Sort key: measured pings first (ascending), everything else last.
    pub fn sort_key(self) -> u32 {
        match self {
            Ping::Ms(ms) => ms,
            _ => u32::MAX,
        }
    }
}

#[cfg(test)]
mod age_tests {
    use super::*;

    #[test]
    fn the_age_of_a_measurement_is_shown() {
        let l = |p, at, now| ping_label_with_age(p, at, now);
        assert_eq!(l(Ping::Ms(42), Some(970), 1000), "42 ms, 30 с назад");
        assert_eq!(
            l(Ping::Ms(42), Some(1000 - 600), 1000),
            "42 ms, 10 мин назад"
        );
        assert_eq!(l(Ping::Timeout, Some(1000), 1000), "timeout, 0 с назад");
        assert_eq!(l(Ping::Unknown, None, 1000), "-");
        assert_eq!(l(Ping::Pending, Some(1), 1000), "...");
    }
}
