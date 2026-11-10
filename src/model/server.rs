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

/// Stage 1 model: only the fields needed to draw the UI.
/// The full model (uuid, flow, Reality params, ...) arrives in stage 2.
#[derive(Debug, Clone)]
pub struct Server {
    pub id: u64,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub security: Security,
    pub transport: Transport,
    pub sni: String,
    pub ping: Ping,
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
