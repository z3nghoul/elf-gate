//! Stage 1 only: fake data and fake background tasks. Removed once real
//! parsing, fetching and the Xray process exist (stages 2-6).

use crate::event::{BgEvent, BgTx, Level, LogLine};
use crate::model::server::{Ping, Security, Server, TlsParams, Transport, TransportParams};
use crate::model::subscription::{Subscription, SubscriptionInfo};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Tiny deterministic-ish pseudo random generator (avoids a `rand` dependency).
pub struct Lcg(pub u64);

impl Lcg {
    pub fn from_clock() -> Self {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        Lcg(n | 1)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

pub fn now_hms() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        % 86_400;
    format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
}

pub fn make_server(id: u64, name: &str, host: &str, sec: Security, tr: Transport) -> Server {
    Server {
        id,
        name: name.to_string(),
        address: host.to_string(),
        port: 443,
        uuid: "00000000-0000-4000-8000-000000000000".into(),
        flow: String::new(),
        security: sec,
        transport: tr,
        tls: TlsParams {
            sni: if sec == Security::None {
                String::new()
            } else {
                "www.example.com".into()
            },
            ..TlsParams::default()
        },
        params: TransportParams::default(),
        link: String::new(),
        unsupported: None,
        ping: Ping::Unknown,
    }
}

pub fn subscriptions(next_id: &mut u64) -> Vec<Subscription> {
    let mut id = || {
        *next_id += 1;
        *next_id
    };
    vec![
        Subscription {
            name: "main".into(),
            collapsed: false,
            info: Some(SubscriptionInfo {
                used: 12_400_000_000,
                total: 100_000_000_000,
                expire: "2027-01-15".into(),
            }),
            servers: vec![
                make_server(
                    id(),
                    "DE-1",
                    "de1.example.com",
                    Security::Reality,
                    Transport::Tcp,
                ),
                make_server(
                    id(),
                    "NL-2",
                    "nl2.example.com",
                    Security::Reality,
                    Transport::Xhttp,
                ),
                make_server(
                    id(),
                    "FI-1",
                    "fi1.example.com",
                    Security::Tls,
                    Transport::Ws,
                ),
                make_server(
                    id(),
                    "Финляндия-3",
                    "fi3.example.com",
                    Security::Tls,
                    Transport::Grpc,
                ),
            ],
        },
        Subscription {
            name: "backup".into(),
            collapsed: false,
            info: None,
            servers: vec![
                make_server(
                    id(),
                    "PL-1",
                    "pl1.example.com",
                    Security::Reality,
                    Transport::Tcp,
                ),
                make_server(
                    id(),
                    "SE-1",
                    "se1.example.com",
                    Security::Reality,
                    Transport::Xhttp,
                ),
                make_server(
                    id(),
                    "US-1",
                    "us1.example.com",
                    Security::Tls,
                    Transport::Ws,
                ),
            ],
        },
    ]
}

const SAMPLES: &[(Level, &str)] = &[
    (Level::Info, "accepted //discord.com:443 [proxy]"),
    (Level::Info, "accepted //gateway.discord.gg:443 [proxy]"),
    (
        Level::Info,
        "accepted //store.steampowered.com:443 [direct]",
    ),
    (Level::Info, "accepted udp:162.159.130.234:50001 [proxy]"),
    (Level::Info, "accepted //cdn.discordapp.com:443 [proxy]"),
    (
        Level::Warning,
        "[Warning] transport/internet/tcp: failed to read response",
    ),
    (Level::Info, "accepted //www.gstatic.com:443 [direct]"),
    (
        Level::Error,
        "[Error] app/proxyman/outbound: connection ends > EOF",
    ),
];

/// Emits a fake log line once a second.
pub fn spawn_log_generator(tx: BgTx) {
    tokio::spawn(async move {
        let mut rng = Lcg::from_clock();
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let (level, text) = SAMPLES[rng.next() as usize % SAMPLES.len()];
            let line = LogLine {
                time: now_hms(),
                level,
                text: text.to_string(),
            };
            if tx.send(BgEvent::Log(line)).is_err() {
                break;
            }
        }
    });
}

pub fn spawn_ping(tx: BgTx, id: u64) {
    tokio::spawn(async move {
        let seed = Lcg::from_clock().0.wrapping_add(id);
        let mut rng = Lcg(seed | 1);
        let delay = 150 + rng.next() % 1200;
        tokio::time::sleep(Duration::from_millis(delay)).await;
        let result = match rng.next() % 10 {
            0 => Ping::Timeout,
            1 => Ping::Error,
            _ => Ping::Ms(20 + (rng.next() % 180) as u32),
        };
        let _ = tx.send(BgEvent::Ping { id, result });
    });
}

/// Fake connection attempt; `ok = false` exercises the error path in the UI.
pub fn spawn_connect(tx: BgTx, id: u64, ok: bool) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(700)).await;
        let ev = if ok {
            BgEvent::Connected(id)
        } else {
            BgEvent::ConnectFailed {
                id,
                reason: "xray exited: failed to dial server (mock)".into(),
            }
        };
        let _ = tx.send(ev);
    });
}

pub fn spawn_update_subs(tx: BgTx) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let _ = tx.send(BgEvent::SubsUpdated);
    });
}
