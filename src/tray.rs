//! The tray icon's data: what the menu shows and which commands it produces. The drawing
//! itself is platform code (`platform::tray_start`); everything here is plain and tested.

use crate::model::rule::TrafficMode;
use crate::proto::{Cmd, Conn, View};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconState {
    Off,
    Connecting,
    On,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayAction {
    Connect,
    Disconnect,
    Select(u64),
    ToggleMode,
    OpenUi,
    Quit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayModel {
    pub state: IconState,
    pub title: String,
    pub servers: Vec<(u64, String)>,
    pub active: Option<u64>,
    pub mode: TrafficMode,
}

impl TrayModel {
    pub fn initial() -> Self {
        Self {
            state: IconState::Off,
            title: "elf-gate: не подключено".into(),
            servers: Vec::new(),
            active: None,
            mode: TrafficMode::Proxy,
        }
    }
}

pub fn model_from_view(v: &View) -> TrayModel {
    let name_of = |id: u64| {
        v.groups
            .iter()
            .flat_map(|g| g.servers.iter())
            .find(|s| s.id == id)
            .map(|s| s.name.clone())
            .unwrap_or_default()
    };
    let (state, title, active) = match &v.conn {
        Conn::Disconnected => (IconState::Off, "elf-gate: не подключено".to_string(), None),
        Conn::Connecting(id) => (
            IconState::Connecting,
            format!("elf-gate: подключение к {}", name_of(*id)),
            Some(*id),
        ),
        Conn::Connected(id) => (
            IconState::On,
            format!("elf-gate: подключено, {}", name_of(*id)),
            Some(*id),
        ),
        Conn::Error(e) => (IconState::Error, format!("elf-gate: ошибка, {e}"), None),
    };
    TrayModel {
        state,
        title,
        servers: v
            .groups
            .iter()
            .flat_map(|g| g.servers.iter())
            .filter(|s| s.is_supported() && !s.hidden)
            .map(|s| (s.id, s.name.clone()))
            .collect(),
        active,
        mode: v.mode,
    }
}

/// The command a tray action means. `last_server` is `[ui].last_server` resolved to an id.
pub fn cmd_for(action: &TrayAction, v: &View) -> Option<Cmd> {
    Some(match action {
        TrayAction::Connect => {
            let wanted = v.config.ui.last_server.as_deref()?;
            let id = v.groups.iter().find_map(|g| {
                g.servers
                    .iter()
                    .find(|s| format!("{}/{}", g.name, s.name) == wanted)
                    .map(|s| s.id)
            })?;
            Cmd::Connect(id)
        }
        TrayAction::Disconnect => Cmd::Disconnect,
        TrayAction::Select(id) => Cmd::Connect(*id),
        TrayAction::ToggleMode => Cmd::ToggleMode,
        TrayAction::Quit => Cmd::Shutdown,
        TrayAction::OpenUi => return None,
    })
}

pub fn mode_label(m: TrafficMode) -> &'static str {
    match m {
        TrafficMode::Proxy => "PROXY",
        TrafficMode::Tun => "TUN",
    }
}

/// A filled circle, RGBA, `size` x `size`: grey (off), amber (connecting), green (on), red (error).
pub fn icon_rgba(state: IconState, size: u32) -> Vec<u8> {
    let (r, g, b) = match state {
        IconState::Off => (140, 140, 140),
        IconState::Connecting => (230, 170, 30),
        IconState::On => (40, 180, 80),
        IconState::Error => (210, 50, 50),
    };
    let c = (size as f32 - 1.0) / 2.0;
    let radius = size as f32 / 2.0 - 1.0;
    let mut px = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let d = ((x as f32 - c).powi(2) + (y as f32 - c).powi(2)).sqrt();
            let a = if d <= radius { 255 } else { 0 };
            px.extend_from_slice(&[r, g, b, a]);
        }
    }
    px
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::tests::view_with;

    #[test]
    fn the_model_follows_the_connection() {
        let mut v = view_with(&["vless://u@h.example.com:443?security=none#One"]);
        assert_eq!(model_from_view(&v).state, IconState::Off);
        v.conn = Conn::Connecting(1);
        assert_eq!(model_from_view(&v).state, IconState::Connecting);
        v.conn = Conn::Connected(1);
        let m = model_from_view(&v);
        assert_eq!((m.state, m.active), (IconState::On, Some(1)));
        assert!(m.title.contains("One"));
        v.conn = Conn::Error("x".into());
        assert_eq!(model_from_view(&v).state, IconState::Error);
        assert_eq!(model_from_view(&v).servers, vec![(1, "One".to_string())]);
    }

    #[test]
    fn actions_become_commands() {
        let mut v = view_with(&["vless://u@h.example.com:443?security=none#One"]);
        assert_eq!(
            cmd_for(&TrayAction::Connect, &v),
            None,
            "no last server yet"
        );
        v.config.ui.last_server = Some("manual/One".into());
        assert_eq!(cmd_for(&TrayAction::Connect, &v), Some(Cmd::Connect(1)));
        assert_eq!(cmd_for(&TrayAction::Select(1), &v), Some(Cmd::Connect(1)));
        assert_eq!(cmd_for(&TrayAction::Quit, &v), Some(Cmd::Shutdown));
        assert_eq!(cmd_for(&TrayAction::OpenUi, &v), None);
    }

    #[test]
    fn icons_have_the_right_size_and_colours() {
        let px = icon_rgba(IconState::On, 16);
        assert_eq!(px.len(), 16 * 16 * 4);
        assert_eq!(&px[(8 * 16 + 8) * 4..][..4], &[40, 180, 80, 255]);
        assert_eq!(px[3], 0, "corners are transparent");
    }
}
