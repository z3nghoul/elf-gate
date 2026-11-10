//! The two ends of the local link: the server side inside the background process and the
//! client side inside the interface. Messages are in [`crate::proto`], one JSON per line.

use crate::engine::Hub;
use crate::event::{LinkEvent, LinkTx};
use crate::platform::{self, BoxStream};
use crate::proto::{decode, encode, Cmd, Update, PROTOCOL_VERSION};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// Serves one connected interface until it goes away.
pub async fn serve_client(stream: BoxStream, hub: std::sync::Arc<Hub>, cmds: UnboundedSender<Cmd>) {
    let (read, mut write) = tokio::io::split(stream);
    let mut feed = hub.subscribe();
    let hello = Update::Hello {
        protocol: PROTOCOL_VERSION,
        version: crate::build_info::VERSION.into(),
    };
    let first = Update::View(Box::new((**feed.view.borrow()).clone()));
    for u in [
        hello,
        first,
        Update::Backlog(std::mem::take(&mut feed.backlog)),
    ] {
        if write.write_all(encode(&u).as_bytes()).await.is_err() {
            return;
        }
    }
    let mut lines = BufReader::new(read).lines();
    loop {
        let out = tokio::select! {
            line = lines.next_line() => match line {
                Ok(Some(l)) => {
                    match decode::<Cmd>(&l) {
                        Ok(cmd) => { let _ = cmds.send(cmd); }
                        Err(e) => tracing::warn!("ipc: bad command: {e}"),
                    }
                    continue;
                }
                _ => return,
            },
            changed = feed.view.changed() => {
                if changed.is_err() { return; }
                Update::View(Box::new((**feed.view.borrow_and_update()).clone()))
            }
            ev = feed.events.recv() => match ev {
                Ok(u) => u,
                // Slow reader: some log lines were dropped, carry on.
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => return,
            },
        };
        let bye = matches!(out, Update::Bye);
        if write.write_all(encode(&out).as_bytes()).await.is_err() || bye {
            return;
        }
    }
}

/// How the interface starts the background part when it is not running.
#[derive(Debug, Clone)]
pub struct Spawn {
    pub program: PathBuf,
    pub args: Vec<String>,
}

impl Spawn {
    /// `elf-gated` beside this executable, else this executable with `--background`.
    pub fn default_for_current_exe() -> Option<Spawn> {
        let me = std::env::current_exe().ok()?;
        let name = format!("elf-gated{}", std::env::consts::EXE_SUFFIX);
        let beside = me.with_file_name(name);
        Some(if beside.is_file() {
            Spawn {
                program: beside,
                args: Vec::new(),
            }
        } else {
            Spawn {
                program: me,
                args: vec!["--background".into()],
            }
        })
    }
}

async fn connect_or_spawn(spawn: Option<&Spawn>) -> Result<BoxStream, String> {
    if let Ok(s) = platform::ipc_connect().await {
        return Ok(s);
    }
    if let Some(sp) = spawn {
        platform::spawn_detached(&sp.program, &sp.args).map_err(|e| e.to_string())?;
    }
    let mut last = crate::t!("ipc.no_answer");
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        match platform::ipc_connect().await {
            Ok(s) => return Ok(s),
            Err(e) => last = e.to_string(),
        }
    }
    Err(crate::t!("ipc.start_timeout", last = last))
}

/// Keeps the link to the background process alive: connects (starting the process if needed),
/// forwards updates to the interface and commands to the process, reconnects when it drops.
pub async fn run_link(events: LinkTx, mut cmds: UnboundedReceiver<Cmd>, spawn: Option<Spawn>) {
    let mut stopped = false;
    loop {
        match connect_or_spawn(spawn.as_ref().filter(|_| !stopped)).await {
            Err(e) => {
                if events.send(LinkEvent::Down(e)).is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            Ok(stream) => {
                let (read, mut write) = tokio::io::split(stream);
                let mut lines = BufReader::new(read).lines();
                let _ = events.send(LinkEvent::Up);
                loop {
                    tokio::select! {
                        line = lines.next_line() => match line {
                            Ok(Some(l)) => match decode::<Update>(&l) {
                                Ok(Update::Hello { protocol, .. }) if protocol != PROTOCOL_VERSION => {
                                    let _ = events.send(LinkEvent::Down(crate::t!(
                                        "ipc.protocol",
                                        protocol = protocol,
                                        need = PROTOCOL_VERSION
                                    )));
                                    break;
                                }
                                Ok(u) => {
                                    stopped |= matches!(u, Update::Bye);
                                    if events.send(LinkEvent::Update(u)).is_err() { return; }
                                }
                                Err(e) => tracing::warn!("ipc: bad update: {e}"),
                            },
                            _ => break,
                        },
                        cmd = cmds.recv() => match cmd {
                            Some(c) => {
                                if write.write_all(encode(&c).as_bytes()).await.is_err() { break; }
                            }
                            None => return,
                        },
                    }
                }
                let _ = events.send(LinkEvent::Down(crate::t!("ipc.lost")));
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}
