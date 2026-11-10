use crate::model::server::Ping;
use crate::xray::process::Core;
use crossterm::event::{Event as TermEvent, EventStream, KeyEvent, KeyEventKind};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{interval, Interval, MissedTickBehavior};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Level {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogLine {
    pub time: String,
    pub level: Level,
    pub text: String,
}

/// Local wall-clock-free `HH:MM:SS` (UTC) used for log lines.
pub fn now_hms() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        % 86_400;
    format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
}

/// Results of background tasks.
#[derive(Debug)]
pub enum BgEvent {
    Log(LogLine),
    Ping {
        id: u64,
        result: Ping,
        kind: crate::model::server::PingKind,
    },
    /// Latency of the live connection (the connection check through the tunnel).
    ActiveLatency {
        id: u64,
        /// The median of the series, or `None` when no request of the series got through.
        ms: Option<u32>,
        samples: u8,
    },
    /// Cumulative traffic counters of the running core.
    Stats(crate::xray::stats::Counters),
    /// A URL ping failed although the server answers over TCP: another fingerprint may help.
    FpSuspect {
        id: u64,
    },
    /// The automatic fingerprint search for server `id` finished.
    FpSearched {
        id: u64,
        xray_version: Option<String>,
        found: Option<String>,
        /// Nothing was tried: the search already ran with this Xray version.
        skipped: bool,
    },
    /// Mock connection (servers without a real link).
    Connected(u64),
    /// The Xray process for server `id` is up and listening.
    CoreStarted {
        id: u64,
        core: Box<Core>,
    },
    CoreFailed {
        id: u64,
        error: String,
        /// The core could not start for lack of rights (TUN): the UI explains how to get them.
        needs_privileges: bool,
    },
    /// Result of the connection check through the local proxy.
    Health {
        id: u64,
        result: Result<std::time::Duration, String>,
    },
    /// A background stop finished; the core ports are free again.
    CoreStopped,
    /// The system proxy was switched on or off by the proxy worker thread.
    ProxyChanged {
        active: bool,
        error: Option<String>,
    },
    /// `xray run -test` refused the config generated for server `id`.
    ServerRejected {
        id: u64,
        reason: String,
    },
    ConnectFailed {
        id: u64,
        reason: String,
    },
    /// A subscription answered (or failed) during an update.
    SubFetched {
        name: String,
        result: Result<Box<SubUpdate>, String>,
    },
    /// The first download of a subscription the user just added.
    SubAdded {
        url: String,
        user_agent: String,
        result: Result<Box<SubUpdate>, String>,
    },
}

/// A downloaded and parsed subscription.
#[derive(Debug)]
pub struct SubUpdate {
    pub servers: Vec<crate::model::server::Server>,
    pub skipped: usize,
    pub info: Option<crate::model::subscription::SubscriptionInfo>,
    pub title: Option<String>,
}

/// What the link to the background process reports to the interface.
#[derive(Debug)]
pub enum LinkEvent {
    /// Connected (again): a view and the log follow.
    Up,
    /// The background process cannot be reached; the link keeps retrying.
    Down(String),
    Update(crate::proto::Update),
}

#[derive(Debug)]
pub enum Event {
    Key(KeyEvent),
    Resize,
    Tick,
    Link(LinkEvent),
}

/// Results of the engine's background tasks.
pub type BgTx = mpsc::UnboundedSender<BgEvent>;
pub type LinkTx = mpsc::UnboundedSender<LinkEvent>;

pub struct EventLoop {
    terminal: EventStream,
    tick: Interval,
    link_rx: mpsc::UnboundedReceiver<LinkEvent>,
}

impl EventLoop {
    pub fn new() -> (Self, LinkTx) {
        let (tx, link_rx) = mpsc::unbounded_channel();
        let mut tick = interval(Duration::from_millis(250));
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        (
            Self {
                terminal: EventStream::new(),
                tick,
                link_rx,
            },
            tx,
        )
    }

    /// Next event; `None` means the terminal input stream is closed.
    pub async fn next(&mut self) -> Option<Event> {
        loop {
            tokio::select! {
                ev = self.terminal.next() => match ev? {
                    Ok(TermEvent::Key(k)) if k.kind != KeyEventKind::Release => {
                        return Some(Event::Key(k));
                    }
                    Ok(TermEvent::Resize(..)) => return Some(Event::Resize),
                    // Mouse, focus, paste, key release, read errors: ignore.
                    _ => {}
                },
                _ = self.tick.tick() => return Some(Event::Tick),
                Some(l) = self.link_rx.recv() => return Some(Event::Link(l)),
            }
        }
    }
}
