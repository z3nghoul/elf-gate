use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Quit,
    /// Quit and stop the background process (the VPN goes down).
    QuitAll,
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
    /// Privacy mode: hide addresses, ids, keys and URLs on the screen.
    Privacy,
    /// Show or hide the servers the user removed from the selected subscription.
    ShowHidden,
    /// Choose the server's role in the primary + backup scheme.
    Role,
    /// Split the TLS ClientHello of the selected server.
    Fragment,
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

/// Where a binding applies (the key bar shows only what works on the current screen).
pub mod scope {
    pub const MAIN: u8 = 1;
    pub const RULES: u8 = 2;
    pub const SETTINGS: u8 = 4;
    pub const LOGS: u8 = 8;
    pub const HELP: u8 = 16;
    pub const ALL: u8 = MAIN | RULES | SETTINGS | LOGS | HELP;
}

pub struct Binding {
    /// Text shown in the help screen.
    pub label: &'static str,
    pub desc: &'static str,
    pub action: Action,
    pub keys: &'static [(KeyCode, KeyModifiers)],
    pub hidden: bool,
    /// The key as written in the key bar (short).
    pub bar: &'static str,
    /// The default caption in the key bar (the screen may refine it for the selected item).
    pub short: &'static str,
    /// 1 = never dropped first, larger = dropped earlier when the window is narrow.
    pub prio: u8,
    /// Bit set of [`scope`] values.
    pub scopes: u8,
}

const N: KeyModifiers = KeyModifiers::NONE;
const C: KeyModifiers = KeyModifiers::CONTROL;

/// Single source of truth for key handling and the help screen.
pub const BINDINGS: &[Binding] = &[
    Binding {
        label: "q / Ctrl+C",
        desc: "закрыть интерфейс (VPN продолжает работать в фоне)",
        action: Action::Quit,
        keys: &[(KeyCode::Char('q'), N), (KeyCode::Char('c'), C)],
        hidden: false,
        bar: "q",
        short: "выход",
        prio: 1,
        scopes: scope::ALL,
    },
    Binding {
        label: "Q",
        desc: "выйти и остановить фоновую часть (VPN отключится)",
        action: Action::QuitAll,
        keys: &[(KeyCode::Char('Q'), N)],
        hidden: false,
        bar: "Q",
        short: "стоп VPN",
        prio: 9,
        scopes: scope::ALL,
    },
    Binding {
        label: "j k / стрелки",
        desc: "перемещение по списку",
        action: Action::Down,
        keys: &[(KeyCode::Char('j'), N), (KeyCode::Down, N)],
        hidden: false,
        bar: "j/k",
        short: "выбор",
        prio: 5,
        scopes: scope::MAIN | scope::RULES | scope::SETTINGS | scope::LOGS,
    },
    Binding {
        label: "",
        desc: "",
        action: Action::Up,
        keys: &[(KeyCode::Char('k'), N), (KeyCode::Up, N)],
        hidden: true,
        bar: "",
        short: "",
        prio: 9,
        scopes: 0,
    },
    Binding {
        label: "PgUp / PgDn",
        desc: "страница вверх / вниз",
        action: Action::PageDown,
        keys: &[(KeyCode::PageDown, N)],
        hidden: false,
        bar: "PgUp/PgDn",
        short: "страница",
        prio: 8,
        scopes: scope::LOGS,
    },
    Binding {
        label: "",
        desc: "",
        action: Action::PageUp,
        keys: &[(KeyCode::PageUp, N)],
        hidden: true,
        bar: "",
        short: "",
        prio: 9,
        scopes: 0,
    },
    Binding {
        label: "g / G",
        desc: "в начало / в конец",
        action: Action::Bottom,
        keys: &[(KeyCode::Char('G'), N), (KeyCode::End, N)],
        hidden: false,
        bar: "g/G",
        short: "начало/конец",
        prio: 8,
        scopes: scope::LOGS,
    },
    Binding {
        label: "",
        desc: "",
        action: Action::Top,
        keys: &[(KeyCode::Char('g'), N), (KeyCode::Home, N)],
        hidden: true,
        bar: "",
        short: "",
        prio: 9,
        scopes: 0,
    },
    Binding {
        label: "Tab / Shift+Tab",
        desc: "переключить панель",
        action: Action::FocusNext,
        keys: &[(KeyCode::Tab, N)],
        hidden: false,
        bar: "Tab",
        short: "панель",
        prio: 7,
        scopes: scope::MAIN,
    },
    Binding {
        label: "",
        desc: "",
        action: Action::FocusPrev,
        keys: &[(KeyCode::BackTab, N)],
        hidden: true,
        bar: "",
        short: "",
        prio: 9,
        scopes: 0,
    },
    Binding {
        label: "Enter",
        desc: "подключиться / отключиться (на текущем сервере) / свернуть группу",
        action: Action::Enter,
        keys: &[(KeyCode::Enter, N)],
        hidden: false,
        bar: "Enter",
        short: "подключить",
        prio: 1,
        scopes: scope::MAIN | scope::SETTINGS,
    },
    Binding {
        label: "d",
        desc: "отключиться",
        action: Action::Disconnect,
        keys: &[(KeyCode::Char('d'), N)],
        hidden: false,
        bar: "d",
        short: "отключить",
        prio: 3,
        scopes: scope::MAIN,
    },
    Binding {
        label: "t",
        desc: "режим PROXY / TUN",
        action: Action::ToggleMode,
        keys: &[(KeyCode::Char('t'), N)],
        hidden: false,
        bar: "t",
        short: "PROXY/TUN",
        prio: 3,
        scopes: scope::MAIN,
    },
    Binding {
        label: "p",
        desc: "пинг всех серверов",
        action: Action::PingAll,
        keys: &[(KeyCode::Char('p'), N)],
        hidden: false,
        bar: "p",
        short: "пинг",
        prio: 4,
        scopes: scope::MAIN,
    },
    Binding {
        label: "o",
        desc: "сортировка по пингу",
        action: Action::SortPing,
        keys: &[(KeyCode::Char('o'), N)],
        hidden: false,
        bar: "o",
        short: "сортировка",
        prio: 7,
        scopes: scope::MAIN,
    },
    Binding {
        label: "u",
        desc: "обновить подписки",
        action: Action::UpdateSubs,
        keys: &[(KeyCode::Char('u'), N)],
        hidden: false,
        bar: "u",
        short: "подписки",
        prio: 5,
        scopes: scope::MAIN,
    },
    Binding {
        label: "a",
        desc: "добавить сервер или подписку по ссылке",
        action: Action::Add,
        keys: &[(KeyCode::Char('a'), N)],
        hidden: false,
        bar: "a",
        short: "добавить",
        prio: 2,
        scopes: scope::MAIN | scope::RULES,
    },
    Binding {
        label: "x",
        desc: "удалить выбранное",
        action: Action::Delete,
        keys: &[(KeyCode::Char('x'), N)],
        hidden: false,
        bar: "x",
        short: "удалить",
        prio: 3,
        scopes: scope::MAIN | scope::RULES,
    },
    Binding {
        label: "r",
        desc: "экран правил",
        action: Action::Rules,
        keys: &[(KeyCode::Char('r'), N)],
        hidden: false,
        bar: "r",
        short: "правила",
        prio: 5,
        scopes: scope::MAIN,
    },
    Binding {
        label: "s",
        desc: "экран настроек",
        action: Action::Settings,
        keys: &[(KeyCode::Char('s'), N)],
        hidden: false,
        bar: "s",
        short: "настройки",
        prio: 5,
        scopes: scope::MAIN,
    },
    Binding {
        label: "l",
        desc: "логи на весь экран",
        action: Action::Logs,
        keys: &[(KeyCode::Char('l'), N)],
        hidden: false,
        bar: "l",
        short: "журнал",
        prio: 6,
        scopes: scope::MAIN,
    },
    Binding {
        label: "/",
        desc: "фильтр списка серверов",
        action: Action::Filter,
        keys: &[(KeyCode::Char('/'), N)],
        hidden: false,
        bar: "/",
        short: "фильтр",
        prio: 6,
        scopes: scope::MAIN,
    },
    Binding {
        label: "Ctrl+P",
        desc: "режим приватности (скрыть адреса, ключи и ссылки на экране)",
        action: Action::Privacy,
        keys: &[(KeyCode::Char('p'), C)],
        hidden: false,
        bar: "Ctrl+P",
        short: "приватность",
        prio: 4,
        scopes: scope::ALL,
    },
    Binding {
        label: "f",
        desc: "сменить TLS fingerprint выбранного сервера",
        action: Action::Fingerprint,
        keys: &[(KeyCode::Char('f'), N)],
        hidden: false,
        bar: "f",
        short: "fp",
        prio: 7,
        scopes: scope::MAIN,
    },
    Binding {
        label: "h",
        desc: "подписка: показать скрытые серверы (вернуть: x на скрытом)",
        action: Action::ShowHidden,
        keys: &[(KeyCode::Char('h'), N)],
        hidden: false,
        bar: "h",
        short: "скрытые",
        prio: 7,
        scopes: scope::MAIN,
    },
    Binding {
        label: "b",
        desc: "роль сервера: основной / запасной (автопереключение)",
        action: Action::Role,
        keys: &[(KeyCode::Char('b'), N)],
        hidden: false,
        bar: "b",
        short: "роль",
        prio: 8,
        scopes: scope::MAIN,
    },
    Binding {
        label: "z",
        desc: "фрагментация TLS ClientHello выбранного сервера",
        action: Action::Fragment,
        keys: &[(KeyCode::Char('z'), N)],
        hidden: false,
        bar: "z",
        short: "фрагмент.",
        prio: 8,
        scopes: scope::MAIN,
    },
    Binding {
        label: "Space",
        desc: "экран правил: включить или выключить правило",
        action: Action::Toggle,
        keys: &[(KeyCode::Char(' '), N)],
        hidden: false,
        bar: "Space",
        short: "вкл/выкл",
        prio: 1,
        scopes: scope::RULES,
    },
    Binding {
        label: "m",
        desc: "экран правил: режим маршрутизации exclude / include",
        action: Action::RoutingMode,
        keys: &[(KeyCode::Char('m'), N)],
        hidden: false,
        bar: "m",
        short: "exclude/include",
        prio: 3,
        scopes: scope::RULES,
    },
    Binding {
        label: "?",
        desc: "справка",
        action: Action::Help,
        keys: &[(KeyCode::Char('?'), N)],
        hidden: false,
        bar: "?",
        short: "помощь",
        prio: 1,
        scopes: scope::ALL,
    },
    Binding {
        label: "Esc",
        desc: "закрыть окно / вернуться",
        action: Action::Back,
        keys: &[(KeyCode::Esc, N)],
        hidden: false,
        bar: "Esc",
        short: "назад",
        prio: 1,
        scopes: scope::RULES | scope::SETTINGS | scope::LOGS | scope::HELP,
    },
    #[cfg(debug_assertions)]
    Binding {
        label: "F12",
        desc: "искусственная паника (debug)",
        action: Action::DebugPanic,
        keys: &[(KeyCode::F(12), N)],
        hidden: true,
        bar: "",
        short: "",
        prio: 9,
        scopes: 0,
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
