//! Tray on Linux: a StatusNotifierItem over D-Bus (`ksni`), no GTK. Without a StatusNotifier
//! host (minimal desktops, GNOME without the AppIndicator extension) `start` fails and the
//! background part simply runs without an icon.

use crate::platform::PlatformError;
use crate::tray::{icon_rgba, mode_label, IconState, TrayAction, TrayModel};
use ksni::menu::{MenuItem, StandardItem, SubMenu};
use ksni::TrayMethods;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::watch;

type OnAction = Arc<dyn Fn(TrayAction) + Send + Sync>;

struct Item {
    model: TrayModel,
    on_action: OnAction,
}

impl Item {
    fn entry(&self, label: &str, action: TrayAction, enabled: bool) -> MenuItem<Self> {
        StandardItem {
            label: label.into(),
            enabled,
            activate: Box::new(move |this: &mut Self| (this.on_action)(action.clone())),
            ..Default::default()
        }
        .into()
    }
}

impl ksni::Tray for Item {
    fn id(&self) -> String {
        "elf-gate".into()
    }
    fn title(&self) -> String {
        self.model.title.clone()
    }
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        let size = 32u32;
        // ARGB32, network byte order.
        let data = icon_rgba(self.model.state, size)
            .chunks(4)
            .flat_map(|p| [p[3], p[0], p[1], p[2]])
            .collect();
        vec![ksni::Icon {
            width: size as i32,
            height: size as i32,
            data,
        }]
    }
    fn menu(&self) -> Vec<MenuItem<Self>> {
        let on = matches!(self.model.state, IconState::On | IconState::Connecting);
        let servers: Vec<MenuItem<Self>> = self
            .model
            .servers
            .iter()
            .map(|(id, name)| {
                let mark = if Some(*id) == self.model.active {
                    "● "
                } else {
                    ""
                };
                self.entry(&format!("{mark}{name}"), TrayAction::Select(*id), true)
            })
            .collect();
        vec![
            StandardItem {
                label: self.model.title.clone(),
                enabled: false,
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            self.entry("Подключиться", TrayAction::Connect, !on),
            self.entry("Отключиться", TrayAction::Disconnect, on),
            SubMenu {
                label: "Сервер".into(),
                enabled: !servers.is_empty(),
                submenu: servers,
                ..Default::default()
            }
            .into(),
            self.entry(
                &format!("Режим: {} (переключить)", mode_label(self.model.mode)),
                TrayAction::ToggleMode,
                true,
            ),
            self.entry("Открыть интерфейс", TrayAction::OpenUi, true),
            MenuItem::Separator,
            self.entry("Выход (отключить VPN)", TrayAction::Quit, true),
        ]
    }
}

pub async fn start(
    mut model: watch::Receiver<TrayModel>,
    on_action: OnAction,
) -> Result<(), String> {
    let item = Item {
        model: model.borrow().clone(),
        on_action,
    };
    let handle = item.spawn().await.map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        while model.changed().await.is_ok() {
            let m = model.borrow_and_update().clone();
            if handle
                .update(move |t: &mut Item| t.model = m)
                .await
                .is_none()
            {
                break;
            }
        }
    });
    Ok(())
}

/// Tries the common terminal emulators; the first one that starts wins.
pub fn open_interface(program: &Path) -> Result<(), PlatformError> {
    let exe = program.display().to_string();
    let candidates: [(&str, &[&str]); 6] = [
        ("x-terminal-emulator", &["-e"]),
        ("konsole", &["-e"]),
        ("gnome-terminal", &["--"]),
        ("alacritty", &["-e"]),
        ("kitty", &[]),
        ("xterm", &["-e"]),
    ];
    for (term, flags) in candidates {
        let mut args: Vec<String> = flags.iter().map(|s| s.to_string()).collect();
        args.push(exe.clone());
        if super::ipc::spawn_detached(Path::new(term), &args).is_ok() {
            return Ok(());
        }
    }
    Err(PlatformError::Failed(
        "не нашёл терминал: запустите elf-gate вручную".into(),
    ))
}
