use crate::model::server::Ping;
use crossterm::event::{Event as TermEvent, EventStream, KeyEvent, KeyEventKind};
use futures_util::StreamExt;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{interval, Interval, MissedTickBehavior};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub struct LogLine {
    pub time: String,
    pub level: Level,
    pub text: String,
}

/// Results of background tasks.
#[derive(Debug)]
pub enum BgEvent {
    Log(LogLine),
    Ping { id: u64, result: Ping },
    Connected(u64),
    ConnectFailed { id: u64, reason: String },
    SubsUpdated,
}

#[derive(Debug)]
pub enum Event {
    Key(KeyEvent),
    Resize,
    Tick,
    Bg(BgEvent),
}

pub type BgTx = mpsc::UnboundedSender<BgEvent>;

pub struct EventLoop {
    terminal: EventStream,
    tick: Interval,
    bg_rx: mpsc::UnboundedReceiver<BgEvent>,
}

impl EventLoop {
    pub fn new() -> (Self, BgTx) {
        let (tx, bg_rx) = mpsc::unbounded_channel();
        let mut tick = interval(Duration::from_millis(250));
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        (
            Self {
                terminal: EventStream::new(),
                tick,
                bg_rx,
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
                Some(bg) = self.bg_rx.recv() => return Some(Event::Bg(bg)),
            }
        }
    }
}
