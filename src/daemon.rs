//! The background process: owns the Xray core, the system proxy, the TUN and the state, and
//! serves the interface over the local link. Closing the interface never touches the VPN.

use crate::engine::Engine;
use crate::event::BgEvent;
use crate::platform::{self, IpcBindError};
use crate::proto::Cmd;
use crate::storage::{self, StateStore, Storage};
use crate::sysproxy::{self, ProxyController, ProxyHandle};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

fn init_logging() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let appender = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("elf-gated.log")
        .max_log_files(7)
        .build(storage::log_dir())
        .ok()?;
    let (writer, guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .try_init()
        .ok()?;
    Some(guard)
}

/// Runs the background process; the return value is the exit code.
/// `args` are the command-line flags (`--tun`: connect to the last server in TUN mode).
pub async fn run(args: &[String]) -> i32 {
    let _log = init_logging();
    // No terminal here: a panic only has to give the system proxy back.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!("panic: {info}");
        sysproxy::emergency_restore();
        previous(info);
    }));

    let mut listener = match platform::ipc_bind() {
        Ok(l) => l,
        Err(IpcBindError::AlreadyRunning) => return 0,
        Err(e) => {
            tracing::error!("{e}");
            return 1;
        }
    };
    let storage = Storage::default_location();
    let config = match storage.load() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("{e}");
            return 1;
        }
    };

    let proxy = Arc::new(ProxyController::new(
        platform::system_proxy(),
        StateStore::default_location(),
    ));
    let recovered = match proxy.recover() {
        Ok(note) => note,
        Err(e) => Some(format!("не удалось восстановить системный прокси: {e}")),
    };
    sysproxy::set_global(proxy.clone());
    let _ = platform::shutdown_signals().install(Box::new(|| {
        sysproxy::emergency_restore();
        std::process::exit(0);
    }));

    let (bg_tx, mut bg_rx) = mpsc::unbounded_channel::<BgEvent>();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<Cmd>();
    let mut engine = Engine::with_config(bg_tx.clone(), config, Some(storage))
        .with_run_dir(storage::state_dir().join("run"))
        .with_proxy(ProxyHandle::spawn(proxy, bg_tx))
        .with_state_store(StateStore::default_location())
        .with_check_cache(storage::state_dir().join("check-cache.json"))
        .with_autostart(platform::autostart().is_enabled());
    engine.startup_tun_cleanup();
    if let Some(note) = recovered {
        engine.log(crate::event::Level::Warning, note);
    }
    engine.start_background_checks();
    if args.iter().any(|a| a == "--tun") {
        engine.start_tun_from_cli();
    } else {
        engine.auto_connect();
    }
    let hub = engine.hub();
    engine.flush_view();

    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    while !engine.should_exit {
        tokio::select! {
            conn = listener.accept() => {
                if let Ok(stream) = conn {
                    tokio::spawn(crate::ipc::serve_client(stream, hub.clone(), cmd_tx.clone()));
                }
            }
            Some(cmd) = cmd_rx.recv() => engine.handle_cmd(cmd),
            Some(ev) = bg_rx.recv() => { engine.on_bg(ev); engine.flush_view(); }
            _ = tick.tick() => engine.on_tick(),
        }
    }
    engine.shutdown().await;
    let relaunch = engine.relaunch_elevated;
    drop(listener);
    storage::fix_owner_tree(&storage::state_dir());
    if relaunch {
        let _ = platform::privileges().relaunch_elevated(&["--tun".to_string()]);
    }
    0
}
