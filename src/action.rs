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

impl Binding {
    /// What the key does, for the help screen (`bind.<Action>.desc` in the locale files).
    pub fn desc(&self) -> String {
        crate::i18n::tr(
            crate::i18n::current(),
            &format!("bind.{:?}.desc", self.action),
            &[],
        )
    }

    /// The default caption in the key bar (the screen may refine it for the selected item).
    pub fn short(&self) -> String {
        crate::i18n::tr(
            crate::i18n::current(),
            &format!("bind.{:?}.short", self.action),
            &[],
        )
    }
}

pub struct Binding {
    /// Text shown in the help screen.
    pub label: &'static str,
    pub action: Action,
    pub keys: &'static [(KeyCode, KeyModifiers)],
    pub hidden: bool,
    /// The key as written in the key bar (short).
    pub bar: &'static str,
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
        action: Action::Quit,
        keys: &[(KeyCode::Char('q'), N), (KeyCode::Char('c'), C)],
        hidden: false,
        bar: "q",
        prio: 1,
        scopes: scope::ALL,
    },
    Binding {
        label: "Q",
        action: Action::QuitAll,
        keys: &[(KeyCode::Char('Q'), N)],
        hidden: false,
        bar: "Q",
        prio: 9,
        scopes: scope::ALL,
    },
    Binding {
        label: "j k / ↑ ↓",
        action: Action::Down,
        keys: &[(KeyCode::Char('j'), N), (KeyCode::Down, N)],
        hidden: false,
        bar: "j/k",
        prio: 5,
        scopes: scope::MAIN | scope::RULES | scope::SETTINGS | scope::LOGS,
    },
    Binding {
        label: "",
        action: Action::Up,
        keys: &[(KeyCode::Char('k'), N), (KeyCode::Up, N)],
        hidden: true,
        bar: "",
        prio: 9,
        scopes: 0,
    },
    Binding {
        label: "PgUp / PgDn",
        action: Action::PageDown,
        keys: &[(KeyCode::PageDown, N)],
        hidden: false,
        bar: "PgUp/PgDn",
        prio: 8,
        scopes: scope::LOGS,
    },
    Binding {
        label: "",
        action: Action::PageUp,
        keys: &[(KeyCode::PageUp, N)],
        hidden: true,
        bar: "",
        prio: 9,
        scopes: 0,
    },
    Binding {
        label: "g / G",
        action: Action::Bottom,
        keys: &[(KeyCode::Char('G'), N), (KeyCode::End, N)],
        hidden: false,
        bar: "g/G",
        prio: 8,
        scopes: scope::LOGS,
    },
    Binding {
        label: "",
        action: Action::Top,
        keys: &[(KeyCode::Char('g'), N), (KeyCode::Home, N)],
        hidden: true,
        bar: "",
        prio: 9,
        scopes: 0,
    },
    Binding {
        label: "Tab / Shift+Tab",
        action: Action::FocusNext,
        keys: &[(KeyCode::Tab, N)],
        hidden: false,
        bar: "Tab",
        prio: 7,
        scopes: scope::MAIN,
    },
    Binding {
        label: "",
        action: Action::FocusPrev,
        keys: &[(KeyCode::BackTab, N)],
        hidden: true,
        bar: "",
        prio: 9,
        scopes: 0,
    },
    Binding {
        label: "Enter",
        action: Action::Enter,
        keys: &[(KeyCode::Enter, N)],
        hidden: false,
        bar: "Enter",
        prio: 1,
        scopes: scope::MAIN | scope::SETTINGS,
    },
    Binding {
        label: "d",
        action: Action::Disconnect,
        keys: &[(KeyCode::Char('d'), N)],
        hidden: false,
        bar: "d",
        prio: 3,
        scopes: scope::MAIN,
    },
    Binding {
        label: "t",
        action: Action::ToggleMode,
        keys: &[(KeyCode::Char('t'), N)],
        hidden: false,
        bar: "t",
        prio: 3,
        scopes: scope::MAIN,
    },
    Binding {
        label: "p",
        action: Action::PingAll,
        keys: &[(KeyCode::Char('p'), N)],
        hidden: false,
        bar: "p",
        prio: 4,
        scopes: scope::MAIN,
    },
    Binding {
        label: "o",
        action: Action::SortPing,
        keys: &[(KeyCode::Char('o'), N)],
        hidden: false,
        bar: "o",
        prio: 7,
        scopes: scope::MAIN,
    },
    Binding {
        label: "u",
        action: Action::UpdateSubs,
        keys: &[(KeyCode::Char('u'), N)],
        hidden: false,
        bar: "u",
        prio: 5,
        scopes: scope::MAIN,
    },
    Binding {
        label: "a",
        action: Action::Add,
        keys: &[(KeyCode::Char('a'), N)],
        hidden: false,
        bar: "a",
        prio: 2,
        scopes: scope::MAIN | scope::RULES,
    },
    Binding {
        label: "x",
        action: Action::Delete,
        keys: &[(KeyCode::Char('x'), N)],
        hidden: false,
        bar: "x",
        prio: 3,
        scopes: scope::MAIN | scope::RULES,
    },
    Binding {
        label: "r",
        action: Action::Rules,
        keys: &[(KeyCode::Char('r'), N)],
        hidden: false,
        bar: "r",
        prio: 5,
        scopes: scope::MAIN,
    },
    Binding {
        label: "s",
        action: Action::Settings,
        keys: &[(KeyCode::Char('s'), N)],
        hidden: false,
        bar: "s",
        prio: 5,
        scopes: scope::MAIN,
    },
    Binding {
        label: "l",
        action: Action::Logs,
        keys: &[(KeyCode::Char('l'), N)],
        hidden: false,
        bar: "l",
        prio: 6,
        scopes: scope::MAIN,
    },
    Binding {
        label: "/",
        action: Action::Filter,
        keys: &[(KeyCode::Char('/'), N)],
        hidden: false,
        bar: "/",
        prio: 6,
        scopes: scope::MAIN,
    },
    Binding {
        label: "Ctrl+P",
        action: Action::Privacy,
        keys: &[(KeyCode::Char('p'), C)],
        hidden: false,
        bar: "Ctrl+P",
        prio: 4,
        scopes: scope::ALL,
    },
    Binding {
        label: "f",
        action: Action::Fingerprint,
        keys: &[(KeyCode::Char('f'), N)],
        hidden: false,
        bar: "f",
        prio: 7,
        scopes: scope::MAIN,
    },
    Binding {
        label: "h",
        action: Action::ShowHidden,
        keys: &[(KeyCode::Char('h'), N)],
        hidden: false,
        bar: "h",
        prio: 7,
        scopes: scope::MAIN,
    },
    Binding {
        label: "b",
        action: Action::Role,
        keys: &[(KeyCode::Char('b'), N)],
        hidden: false,
        bar: "b",
        prio: 8,
        scopes: scope::MAIN,
    },
    Binding {
        label: "z",
        action: Action::Fragment,
        keys: &[(KeyCode::Char('z'), N)],
        hidden: false,
        bar: "z",
        prio: 8,
        scopes: scope::MAIN,
    },
    Binding {
        label: "Space",
        action: Action::Toggle,
        keys: &[(KeyCode::Char(' '), N)],
        hidden: false,
        bar: "Space",
        prio: 1,
        scopes: scope::RULES,
    },
    Binding {
        label: "m",
        action: Action::RoutingMode,
        keys: &[(KeyCode::Char('m'), N)],
        hidden: false,
        bar: "m",
        prio: 3,
        scopes: scope::RULES,
    },
    Binding {
        label: "?",
        action: Action::Help,
        keys: &[(KeyCode::Char('?'), N)],
        hidden: false,
        bar: "?",
        prio: 1,
        scopes: scope::ALL,
    },
    Binding {
        label: "Esc",
        action: Action::Back,
        keys: &[(KeyCode::Esc, N)],
        hidden: false,
        bar: "Esc",
        prio: 1,
        scopes: scope::RULES | scope::SETTINGS | scope::LOGS | scope::HELP,
    },
    #[cfg(debug_assertions)]
    Binding {
        label: "F12",
        action: Action::DebugPanic,
        keys: &[(KeyCode::F(12), N)],
        hidden: true,
        bar: "",
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
