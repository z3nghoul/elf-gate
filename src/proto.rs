//! What the background process (`elf-gated`) and the interface (`elf-gate`) say to each other.
//!
//! One JSON object per line in both directions. The interface sends [`Cmd`], the background
//! process answers with [`Update`]. Server links and secrets never cross this boundary: the
//! interface sees names, addresses and the parameters its screens show ([`View`]).

use crate::event::LogLine;
use crate::model::rule::{RoutingMode, RuleKind, TrafficMode};
use crate::model::server::ServerRole;
use crate::model::subscription::Subscription;
use crate::storage::Config;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Bumped when messages change incompatibly; a mismatch is reported to the user.
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Conn {
    Disconnected,
    Connecting(u64),
    Connected(u64),
    Error(String),
}

/// The connection check after the core started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthState {
    Unknown,
    Checking,
    Ok(Duration),
    Failed(String),
}

/// Which item of the rules screen a command means.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleRef {
    Preset(String),
    Rule(usize),
}

/// A setting the settings screen may change (stage 8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Setting {
    XrayPath(String),
    TunXrayPath(String),
    SocksPort(u16),
    HttpPort(u16),
    ApiPort(u16),
    LogLevel(String),
    SetSystemProxy(bool),
    PingMode(crate::storage::PingMode),
    PingUrl(String),
    PingTimeoutMs(u64),
    TunName(String),
    TunnelDns(String),
    AutoConnect(bool),
    Autostart(bool),
    Theme(String),
    /// `[[subscriptions]]` entry by name.
    SubscriptionUserAgent {
        name: String,
        value: String,
    },
    SubscriptionHours {
        name: String,
        hours: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Cmd {
    Connect(u64),
    Disconnect,
    ToggleMode,
    PingAll,
    UpdateSubs,
    /// A server link or a subscription URL typed by the user.
    AddLink(String),
    DeleteServer(u64),
    DeleteGroup(String),
    SetFingerprint {
        id: u64,
        fp: Option<String>,
    },
    SetRole {
        id: u64,
        role: Option<ServerRole>,
    },
    SetFragment {
        id: u64,
        on: bool,
    },
    ToggleRule(RuleRef),
    DeleteRule(usize),
    AddRule {
        kind: RuleKind,
        value: String,
    },
    SetRouting(RoutingMode),
    /// The answer to a question the background process asked.
    Answer {
        ask: Ask,
        yes: bool,
    },
    Set(Setting),
    /// `elf-gate --tun`: switch to TUN and connect to the last server.
    ConnectLastInTun,
    /// Windows: restart the background process with administrator rights.
    RelaunchElevated,
    /// Stop the VPN and the background process.
    Shutdown,
}

/// A question for the user; the answer comes back as [`Cmd::Answer`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ask {
    /// First TUN start: offer the discord-only preset, then connect to this server.
    PresetOffer(u64),
    /// Windows: restart with administrator rights.
    RelaunchElevated,
    /// Rules changed while connected: restart the core to apply them.
    ApplyRules(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Alert {
    Error(String),
    Notice(String),
    Ask { text: String, ask: Ask },
}

/// Traffic of the current session (stage 8): bytes and speed, `proxy` and `direct` apart.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Traffic {
    pub proxy_up: u64,
    pub proxy_down: u64,
    pub direct_up: u64,
    pub direct_down: u64,
    /// Bytes per second over the last interval.
    pub speed_up: u64,
    pub speed_down: u64,
}

/// Everything the screens need to draw, a snapshot of the background process's state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct View {
    pub groups: Vec<Subscription>,
    pub conn: Conn,
    pub mode: TrafficMode,
    /// The mode the live connection runs in (the mode may be toggled meanwhile).
    pub conn_mode: TrafficMode,
    pub tun_active: bool,
    pub proxy_active: bool,
    pub health: HealthState,
    /// Without server links and subscription URLs, see [`Config::redacted`].
    pub config: Config,
    pub traffic: Traffic,
    /// The tray icon exists (the interface can say so in the settings).
    pub tray: bool,
    /// Autostart is switched on in the OS.
    pub autostart: bool,
    /// Demo data (debug builds).
    pub mock: bool,
    pub pid: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Update {
    Hello {
        protocol: u32,
        version: String,
    },
    View(Box<View>),
    /// The log so far, sent once after the hello.
    Backlog(Vec<LogLine>),
    Log(LogLine),
    Alert(Alert),
    Status(String),
    /// The background process is stopping.
    Bye,
}

/// One line on the wire.
pub fn encode<T: Serialize>(msg: &T) -> String {
    let mut line = serde_json::to_string(msg).unwrap_or_else(|_| "null".into());
    line.push('\n');
    line
}

pub fn decode<'a, T: Deserialize<'a>>(line: &'a str) -> Result<T, String> {
    serde_json::from_str(line.trim_end()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_roundtrip_as_single_lines() {
        for cmd in [
            Cmd::Connect(7),
            Cmd::SetRole {
                id: 3,
                role: Some(ServerRole::Backup),
            },
            Cmd::Answer {
                ask: Ask::PresetOffer(9),
                yes: true,
            },
            Cmd::Set(Setting::SocksPort(1080)),
            Cmd::AddLink("vless://x@y:1#z\nignored".into()),
        ] {
            let line = encode(&cmd);
            assert_eq!(
                line.matches('\n').count(),
                1,
                "newlines must be escaped: {line:?}"
            );
            assert_eq!(decode::<Cmd>(&line).unwrap(), cmd);
        }
    }

    #[test]
    fn a_view_never_carries_links_or_keys() {
        use crate::parser::parse_link;
        let server = parse_link(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@h.example.com:443?security=reality&sni=x.org&pbk=SECRETKEY&sid=abcd&fp=chrome#R",
        )
        .unwrap();
        let mut config = Config::default();
        config.servers.push(crate::storage::ServerEntry {
            link: server.link.clone(),
        });
        config
            .subscriptions
            .push(crate::storage::SubscriptionConfig {
                name: "p".into(),
                url: "https://prov.example/sub/TOKEN".into(),
                ..Default::default()
            });
        let view = View {
            groups: vec![Subscription {
                name: "g".into(),
                servers: vec![server.redacted()],
                collapsed: false,
                info: None,
                updated: None,
                is_remote: false,
            }],
            conn: Conn::Disconnected,
            mode: TrafficMode::Proxy,
            conn_mode: TrafficMode::Proxy,
            tun_active: false,
            proxy_active: false,
            health: HealthState::Unknown,
            config: config.redacted(),
            traffic: Traffic::default(),
            tray: false,
            autostart: false,
            mock: false,
            pid: 1,
        };
        let wire = encode(&Update::View(Box::new(view.clone())));
        for secret in [
            "SECRETKEY",
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            "abcd",
            "TOKEN",
            "vless://",
        ] {
            assert!(!wire.contains(secret), "{secret} leaked: {wire}");
        }
        assert!(wire.contains("h.example.com"), "addresses are shown");
        assert_eq!(
            decode::<Update>(&wire).unwrap(),
            Update::View(Box::new(view))
        );
    }
}
