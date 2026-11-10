use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Quit,
    Up,
    Down,
    PageUp,
    PageDown,
    Top,
    Bottom,
    Enter,
    Disconnect,
    ToggleMode,
    PingAll,
    SortPing,
    UpdateSubs,
    Add,
    Delete,
    Rules,
    Settings,
    Logs,
    Filter,
    Fingerprint,
    /// Rules screen: enable or disable the selected rule or preset.
    Toggle,
    /// Rules screen: switch between `exclude` and `include`.
    RoutingMode,
    Help,
    Back,
    FocusNext,
    FocusPrev,
    #[cfg(debug_assertions)]
    DebugPanic,
}

pub struct Binding {
    /// Text shown in the help screen.
    pub label: &'static str,
    pub desc: &'static str,
    pub action: Action,
    pub keys: &'static [(KeyCode, KeyModifiers)],
    pub hidden: bool,
}

const N: KeyModifiers = KeyModifiers::NONE;
const C: KeyModifiers = KeyModifiers::CONTROL;

/// Single source of truth for key handling and the help screen.
pub const BINDINGS: &[Binding] = &[
    Binding {
        label: "q / Ctrl+C",
        desc: "выход (с подтверждением, если подключено)",
        action: Action::Quit,
        keys: &[(KeyCode::Char('q'), N), (KeyCode::Char('c'), C)],
        hidden: false,
    },
    Binding {
        label: "j k / стрелки",
        desc: "перемещение по списку",
        action: Action::Down,
        keys: &[(KeyCode::Char('j'), N), (KeyCode::Down, N)],
        hidden: false,
    },
    Binding {
        label: "",
        desc: "",
        action: Action::Up,
        keys: &[(KeyCode::Char('k'), N), (KeyCode::Up, N)],
        hidden: true,
    },
    Binding {
        label: "PgUp / PgDn",
        desc: "страница вверх / вниз",
        action: Action::PageDown,
        keys: &[(KeyCode::PageDown, N)],
        hidden: false,
    },
    Binding {
        label: "",
        desc: "",
        action: Action::PageUp,
        keys: &[(KeyCode::PageUp, N)],
        hidden: true,
    },
    Binding {
        label: "g / G",
        desc: "в начало / в конец",
        action: Action::Bottom,
        keys: &[(KeyCode::Char('G'), N), (KeyCode::End, N)],
        hidden: false,
    },
    Binding {
        label: "",
        desc: "",
        action: Action::Top,
        keys: &[(KeyCode::Char('g'), N), (KeyCode::Home, N)],
        hidden: true,
    },
    Binding {
        label: "Tab / Shift+Tab",
        desc: "переключить панель",
        action: Action::FocusNext,
        keys: &[(KeyCode::Tab, N)],
        hidden: false,
    },
    Binding {
        label: "",
        desc: "",
        action: Action::FocusPrev,
        keys: &[(KeyCode::BackTab, N)],
        hidden: true,
    },
    Binding {
        label: "Enter",
        desc: "подключиться / свернуть группу",
        action: Action::Enter,
        keys: &[(KeyCode::Enter, N)],
        hidden: false,
    },
    Binding {
        label: "d",
        desc: "отключиться",
        action: Action::Disconnect,
        keys: &[(KeyCode::Char('d'), N)],
        hidden: false,
    },
    Binding {
        label: "t",
        desc: "режим PROXY / TUN",
        action: Action::ToggleMode,
        keys: &[(KeyCode::Char('t'), N)],
        hidden: false,
    },
    Binding {
        label: "p",
        desc: "пинг всех серверов",
        action: Action::PingAll,
        keys: &[(KeyCode::Char('p'), N)],
        hidden: false,
    },
    Binding {
        label: "o",
        desc: "сортировка по пингу",
        action: Action::SortPing,
        keys: &[(KeyCode::Char('o'), N)],
        hidden: false,
    },
    Binding {
        label: "u",
        desc: "обновить подписки",
        action: Action::UpdateSubs,
        keys: &[(KeyCode::Char('u'), N)],
        hidden: false,
    },
    Binding {
        label: "a",
        desc: "добавить сервер или подписку по ссылке",
        action: Action::Add,
        keys: &[(KeyCode::Char('a'), N)],
        hidden: false,
    },
    Binding {
        label: "x",
        desc: "удалить выбранное",
        action: Action::Delete,
        keys: &[(KeyCode::Char('x'), N)],
        hidden: false,
    },
    Binding {
        label: "r",
        desc: "экран правил",
        action: Action::Rules,
        keys: &[(KeyCode::Char('r'), N)],
        hidden: false,
    },
    Binding {
        label: "s",
        desc: "экран настроек",
        action: Action::Settings,
        keys: &[(KeyCode::Char('s'), N)],
        hidden: false,
    },
    Binding {
        label: "l",
        desc: "логи на весь экран",
        action: Action::Logs,
        keys: &[(KeyCode::Char('l'), N)],
        hidden: false,
    },
    Binding {
        label: "/",
        desc: "фильтр списка серверов",
        action: Action::Filter,
        keys: &[(KeyCode::Char('/'), N)],
        hidden: false,
    },
    Binding {
        label: "f",
        desc: "сменить TLS fingerprint выбранного сервера",
        action: Action::Fingerprint,
        keys: &[(KeyCode::Char('f'), N)],
        hidden: false,
    },
    Binding {
        label: "Space",
        desc: "экран правил: включить или выключить правило",
        action: Action::Toggle,
        keys: &[(KeyCode::Char(' '), N)],
        hidden: false,
    },
    Binding {
        label: "m",
        desc: "экран правил: режим маршрутизации exclude / include",
        action: Action::RoutingMode,
        keys: &[(KeyCode::Char('m'), N)],
        hidden: false,
    },
    Binding {
        label: "?",
        desc: "справка",
        action: Action::Help,
        keys: &[(KeyCode::Char('?'), N)],
        hidden: false,
    },
    Binding {
        label: "Esc",
        desc: "закрыть окно / вернуться",
        action: Action::Back,
        keys: &[(KeyCode::Esc, N)],
        hidden: false,
    },
    #[cfg(debug_assertions)]
    Binding {
        label: "F12",
        desc: "искусственная паника (debug)",
        action: Action::DebugPanic,
        keys: &[(KeyCode::F(12), N)],
        hidden: true,
    },
];

/// Maps a key press to an action. SHIFT is ignored (it is already encoded in
/// the character, and BackTab always carries it).
pub fn map_key(key: KeyEvent) -> Option<Action> {
    let mods = key.modifiers - KeyModifiers::SHIFT;
    BINDINGS
        .iter()
        .find(|b| b.keys.iter().any(|(c, m)| *c == key.code && *m == mods))
        .map(|b| b.action)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_basic_keys() {
        let k = |c, m| KeyEvent::new(c, m);
        assert_eq!(map_key(k(KeyCode::Char('q'), N)), Some(Action::Quit));
        assert_eq!(map_key(k(KeyCode::Char('c'), C)), Some(Action::Quit));
        assert_eq!(map_key(k(KeyCode::Char('c'), N)), None);
        assert_eq!(
            map_key(k(KeyCode::BackTab, KeyModifiers::SHIFT)),
            Some(Action::FocusPrev)
        );
        assert_eq!(
            map_key(k(KeyCode::Char('G'), KeyModifiers::SHIFT)),
            Some(Action::Bottom)
        );
    }

    #[test]
    fn no_duplicate_keys() {
        let mut seen = Vec::new();
        for b in BINDINGS {
            for key in b.keys {
                assert!(!seen.contains(key), "duplicate binding {key:?}");
                seen.push(*key);
            }
        }
    }
}
