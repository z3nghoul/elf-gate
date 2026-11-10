//! Tray on Windows: `tray-icon` (Win32 notification area) with its menu, on a thread that
//! runs the message loop. The background process has no console, so this is the only
//! visible part of it.

use crate::platform::PlatformError;
use crate::tray::{icon_rgba, mode_label, IconState, TrayAction, TrayModel};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::watch;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, TrayIconBuilder};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
};

type OnAction = Arc<dyn Fn(TrayAction) + Send + Sync>;

fn build_menu(m: &TrayModel) -> Menu {
    let menu = Menu::new();
    let on = matches!(m.state, IconState::On | IconState::Connecting);
    let _ = menu.append(&MenuItem::with_id("title", &m.title, false, None));
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&MenuItem::with_id("connect", "Подключиться", !on, None));
    let _ = menu.append(&MenuItem::with_id("disconnect", "Отключиться", on, None));
    let servers = Submenu::with_id("servers", "Сервер", !m.servers.is_empty());
    for (id, name) in &m.servers {
        let mark = if Some(*id) == m.active { "● " } else { "" };
        let _ = servers.append(&MenuItem::with_id(
            format!("sel:{id}"),
            format!("{mark}{name}"),
            true,
            None,
        ));
    }
    let _ = menu.append(&servers);
    let _ = menu.append(&MenuItem::with_id(
        "mode",
        format!("Режим: {} (переключить)", mode_label(m.mode)),
        true,
        None,
    ));
    let _ = menu.append(&MenuItem::with_id("open", "Открыть интерфейс", true, None));
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&MenuItem::with_id(
        "quit",
        "Выход (отключить VPN)",
        true,
        None,
    ));
    menu
}

fn action_for(id: &str) -> Option<TrayAction> {
    Some(match id {
        "connect" => TrayAction::Connect,
        "disconnect" => TrayAction::Disconnect,
        "mode" => TrayAction::ToggleMode,
        "open" => TrayAction::OpenUi,
        "quit" => TrayAction::Quit,
        s => TrayAction::Select(s.strip_prefix("sel:")?.parse().ok()?),
    })
}

fn icon(state: IconState) -> Option<Icon> {
    Icon::from_rgba(icon_rgba(state, 32), 32, 32).ok()
}

pub async fn start(model: watch::Receiver<TrayModel>, on_action: OnAction) -> Result<(), String> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    std::thread::spawn(move || {
        let mut model = model;
        let first = model.borrow().clone();
        let Some(ic) = icon(first.state) else {
            let _ = ready_tx.send(Err("не удалось создать значок".into()));
            return;
        };
        let tray = match TrayIconBuilder::new()
            .with_icon(ic)
            .with_tooltip(&first.title)
            .with_menu(Box::new(build_menu(&first)))
            .build()
        {
            Ok(t) => t,
            Err(e) => {
                let _ = ready_tx.send(Err(e.to_string()));
                return;
            }
        };
        let _ = ready_tx.send(Ok(()));
        loop {
            // The notification area needs a message loop on the thread that owns the icon.
            // SAFETY: standard Win32 message pump; `msg` is a valid out structure.
            unsafe {
                let mut msg = MSG::default();
                while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
            while let Ok(ev) = MenuEvent::receiver().try_recv() {
                if let Some(a) = action_for(ev.id.as_ref()) {
                    on_action(a);
                }
            }
            if model.has_changed().unwrap_or(false) {
                let m = model.borrow_and_update().clone();
                if let Some(ic) = icon(m.state) {
                    let _ = tray.set_icon(Some(ic));
                }
                let _ = tray.set_tooltip(Some(&m.title));
                tray.set_menu(Some(Box::new(build_menu(&m))));
            } else if model.has_changed().is_err() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    });
    ready_rx.recv().map_err(|e| e.to_string())?
}

/// Windows Terminal if present, else the default console host.
pub fn open_interface(program: &Path) -> Result<(), PlatformError> {
    let exe = program.display().to_string();
    if super::ipc::spawn_detached(Path::new("wt.exe"), &[exe.clone()]).is_ok() {
        return Ok(());
    }
    super::ipc::spawn_detached(
        Path::new("cmd.exe"),
        &["/c".into(), "start".into(), "".into(), exe],
    )
}
