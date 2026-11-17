//! `elf-gate`: the interface. The VPN itself lives in the background process (`elf-gated`),
//! which this program starts when needed and talks to over a local link.

use anyhow::Result;
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use elf_gate::app::AppState;
use elf_gate::event::EventLoop;
use elf_gate::ipc::{self, Spawn};
use elf_gate::proto::Cmd;
use elf_gate::{build_info, daemon, platform, storage, ui};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::{self, Stdout};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};

type Term = Terminal<CrosstermBackend<Stdout>>;

fn init_logging() -> Option<WorkerGuard> {
    storage::prepare_private_files();
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
    // The mouse goes back to the terminal here too: the panic hook calls this function.
    let _ = execute!(io::stdout(), DisableMouseCapture, LeaveAlternateScreen);
}

fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        tracing::error!("panic: {info}");
        // The VPN lives in the background process: a crash here changes nothing for it.
        previous(info);
    }));
}

fn setup_terminal() -> Result<Term> {
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(io::stdout()))?)
}

async fn run(terminal: &mut Term, tun_from_cli: bool, colors: ui::theme::ColorMode) -> Result<()> {
    let (mut events, link_tx) = EventLoop::new();
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Cmd>();
    let mut app = AppState::new(cmd_tx.clone());
    if tun_from_cli {
        let _ = cmd_tx.send(Cmd::ConnectLastInTun);
    }
    tokio::spawn(ipc::run_link(
        link_tx,
        cmd_rx,
        Spawn::default_for_current_exe(),
    ));

    let mut forced_logged = false;
    let mut mouse_captured = false;
    while !app.should_quit {
        // The "Mouse" setting applies at once: the terminal hands over the mouse events only
        // while it is on (and selects text itself while it is off).
        if app.config.ui.mouse != mouse_captured {
            mouse_captured = app.config.ui.mouse;
            // A terminal without mouse support may refuse: the keyboard works all the same.
            let result = if mouse_captured {
                execute!(io::stdout(), EnableMouseCapture)
            } else {
                execute!(io::stdout(), DisableMouseCapture)
            };
            if let Err(e) = result {
                tracing::debug!("mouse capture not changed: {e}");
            }
        }
        if app.take_redraw() {
            terminal.clear()?;
        }
        terminal.draw(|f| {
            let ctx = ui::RenderCtx::native(&app.config.ui, colors);
            if !forced_logged && ui::theme::Theme::resolve(&app.config.ui.theme, colors, false).1 {
                forced_logged = true;
                tracing::warn!(
                    "the terminal has no 256 colours: the terminal theme is used instead of {}",
                    app.config.ui.theme
                );
            }
            ui::render(f, &mut app, &ctx)
        })?;
        match events.next().await {
            Some(ev) => app.handle_event(ev),
            None => break,
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--supervise") {
        // Hidden mode: a tiny process that keeps a privileged core tied to its parent
        // (the kernel drops the parent-death signal for binaries with capabilities).
        std::process::exit(platform::run_supervisor(&args[1..]));
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("{}", build_info::version_line());
        return Ok(());
    }
    if args.iter().any(|a| a == "--background") {
        std::process::exit(daemon::run(&args).await);
    }
    let _log_guard = init_logging();
    install_panic_hook();
    let mut terminal = setup_terminal()?;
    let tun = args.iter().any(|a| a == "--tun");
    let colors = ui::theme::ColorMode::detect();
    tracing::info!("colour mode: {colors:?}");
    let result = run(&mut terminal, tun, colors).await;
    restore_terminal();
    if let Err(e) = &result {
        tracing::error!("fatal: {e:#}");
    }
    result
}
