#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    None,
    Tls,
    Reality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Xhttp,
    Grpc,
    Ws,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ping {
    Unknown,
    Pending,
    Ms(u32),
    Timeout,
    Error,
}

/// TLS / Reality parameters from the link query.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransportParams {
    pub path: String,
    pub host: String,
    /// xhttp `mode`.
    pub mode: String,
    /// grpc `serviceName`.
    pub service_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// Runtime id, assigned by the application (not persisted).
    pub id: u64,
    pub name: String,
    /// Host without IPv6 brackets.
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub flow: String,
    pub security: Security,
    pub transport: Transport,
    pub tls: TlsParams,
    pub params: TransportParams,
    /// The original link, exactly as the user supplied it.
    pub link: String,
    /// `Some(reason)` when the server was imported but cannot be used yet.
    pub unsupported: Option<String>,
    pub ping: Ping,
}

impl Server {
    /// A placeholder for links we recognise but do not support (vmess, trojan, ...).
    pub fn unsupported(link: &str, name: String, reason: String) -> Self {
        Self {
            id: 0,
            name,
            address: String::new(),
            port: 0,
            uuid: String::new(),
            flow: String::new(),
            security: Security::None,
            transport: Transport::Tcp,
            tls: TlsParams::default(),
            params: TransportParams::default(),
            link: link.to_string(),
            unsupported: Some(reason),
            ping: Ping::Unknown,
        }
    }

    pub fn is_supported(&self) -> bool {
        self.unsupported.is_none()
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
