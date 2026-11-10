mod action;
mod app;
mod event;
mod mock;
mod model;
mod parser;
// Stage 1 ships only empty platform implementations; they get used from stage 3 on.
#[allow(dead_code)]
mod platform;
mod storage;
mod ui;
mod xray;

use anyhow::Result;
use app::AppState;
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use event::EventLoop;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::{self, Stdout};
use storage::{Config, Storage};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};

type Term = Terminal<CrosstermBackend<Stdout>>;

fn init_logging() -> Option<WorkerGuard> {
    // stdout belongs to the TUI: logs go to a file only.
    let appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("elf-gate.log")
        .max_log_files(7)
        .build(storage::log_dir())
        .ok()?;
    let (writer, guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .init();
    Some(guard)
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
}

fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        tracing::error!("panic: {info}");
        // Later stages: disable system proxy, stop core and TUN here.
        previous(info);
    }));
}

fn setup_terminal() -> Result<Term> {
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(io::stdout()))?)
}

async fn run(terminal: &mut Term, config: Config, storage: Storage) -> Result<()> {
    let (mut events, tx) = EventLoop::new();
    mock::spawn_log_generator(tx.clone());
    let mut app = AppState::with_config(tx, config, Some(storage))
        .with_run_dir(storage::state_dir().join("run"));
    app.start_background_checks();

    while !app.should_quit {
        terminal.draw(|f| ui::render(f, &mut app))?;
        match events.next().await {
            Some(ev) => app.handle_event(ev),
            None => break,
        }
    }
    app.shutdown().await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let _log_guard = init_logging();
    install_panic_hook();
    // Load before touching the terminal: a broken config must be reported, not overwritten.
    let storage = Storage::default_location();
    let config = match storage.load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("elf-gate: {e}");
            std::process::exit(1);
        }
    };
    let mut terminal = setup_terminal()?;
    let result = run(&mut terminal, config, storage).await;
    restore_terminal();
    if let Err(e) = &result {
        tracing::error!("fatal: {e:#}");
    }
    result
}
