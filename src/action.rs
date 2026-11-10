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
    /// Ctrl+L: clear and redraw the whole screen (after the terminal garbled it).
    Redraw,
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
    Binding {
        label: "Ctrl+L",
        action: Action::Redraw,
        keys: &[(KeyCode::Char('l'), C)],
        hidden: false,
        bar: "Ctrl+L",
        prio: 9,
        // Only in the help screen: the bar has no room for a key needed once in a blue moon.
        scopes: 0,
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

/// Physical keys of the Russian and the Ukrainian layouts: `(QWERTY, Russian, Ukrainian)`, all
/// in lower case. A hotkey typed with a Cyrillic layout on is the binding of the QWERTY key at the
/// same place. The bindings themselves stay in [`BINDINGS`] only; this is just the layouts.
/// The Cyrillic characters are written as escapes (the sources keep no Cyrillic).
pub const LAYOUT_KEYS: &[(char, char, char)] = &[
    ('q', '\u{439}', '\u{439}'), // ru/uk: Y-short
    ('w', '\u{446}', '\u{446}'),
    ('e', '\u{443}', '\u{443}'),
    ('r', '\u{43a}', '\u{43a}'),
    ('t', '\u{435}', '\u{435}'),
    ('y', '\u{43d}', '\u{43d}'),
    ('u', '\u{433}', '\u{433}'),
    ('i', '\u{448}', '\u{448}'),
    ('o', '\u{449}', '\u{449}'),
    ('p', '\u{437}', '\u{437}'),
    ('[', '\u{445}', '\u{445}'),
    (']', '\u{44a}', '\u{457}'), // ru hard sign / uk yi
    ('a', '\u{444}', '\u{444}'),
    ('s', '\u{44b}', '\u{456}'), // ru yery / uk i
    ('d', '\u{432}', '\u{432}'),
    ('f', '\u{430}', '\u{430}'),
    ('g', '\u{43f}', '\u{43f}'),
    ('h', '\u{440}', '\u{440}'),
    ('j', '\u{43e}', '\u{43e}'),
    ('k', '\u{43b}', '\u{43b}'),
    ('l', '\u{434}', '\u{434}'),
    (';', '\u{436}', '\u{436}'),
    ('\'', '\u{44d}', '\u{454}'), // ru e-reverse / uk ye
    ('z', '\u{44f}', '\u{44f}'),
    ('x', '\u{447}', '\u{447}'),
    ('c', '\u{441}', '\u{441}'),
    ('v', '\u{43c}', '\u{43c}'),
    ('b', '\u{438}', '\u{438}'),
    ('n', '\u{442}', '\u{442}'),
    ('m', '\u{44c}', '\u{44c}'),
    (',', '\u{431}', '\u{431}'),
    ('.', '\u{44e}', '\u{44e}'),
];

/// The QWERTY character on the physical key where `c` sits in the Russian or Ukrainian layout;
/// the case is kept (capital Y-short is `Q`). Anything else is returned as it is.
pub fn qwerty(c: char) -> char {
    let lower = c.to_lowercase().next().unwrap_or(c);
    let upper = lower != c;
    match LAYOUT_KEYS
        .iter()
        .find(|(_, ru, uk)| *ru == lower || *uk == lower)
    {
        Some((q, _, _)) if upper => q.to_ascii_uppercase(),
        Some((q, _, _)) => *q,
        None => c,
    }
}

fn lookup(code: KeyCode, mods: KeyModifiers) -> Option<Action> {
    BINDINGS
        .iter()
        .find(|b| b.keys.iter().any(|(c, m)| *c == code && *m == mods))
        .map(|b| b.action)
}

/// Maps a key press to an action. SHIFT is ignored (it is already encoded in the character,
/// and BackTab always carries it). A key typed in the Russian or Ukrainian layout works as the
/// QWERTY key in the same place (also with Ctrl). Only hotkeys come here: text fields take the
/// characters as they are.
pub fn map_key(key: KeyEvent) -> Option<Action> {
    let mods = key.modifiers - KeyModifiers::SHIFT;
    lookup(key.code, mods).or_else(|| match key.code {
        KeyCode::Char(c) => {
            let q = qwerty(c);
            if q == c {
                None
            } else {
                lookup(KeyCode::Char(q), mods)
            }
        }
        _ => None,
    })
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

    /// A character of a layout for a binding's QWERTY character, case kept.
    fn typed(q: char, layout: usize) -> char {
        let lower = q.to_ascii_lowercase();
        let (_, ru, uk) = LAYOUT_KEYS
            .iter()
            .find(|(l, ..)| *l == lower)
            .unwrap_or_else(|| panic!("`{q}` has no key in the layout table"));
        let c = if layout == 0 { *ru } else { *uk };
        if q.is_ascii_uppercase() {
            c.to_uppercase().next().unwrap()
        } else {
            c
        }
    }

    #[test]
    fn every_letter_binding_fires_from_qwerty_russian_and_ukrainian_of_the_same_key() {
        let mut checked = 0;
        for b in BINDINGS {
            for (code, mods) in b.keys {
                let KeyCode::Char(q) = code else { continue };
                if !LAYOUT_KEYS
                    .iter()
                    .any(|(l, ..)| *l == q.to_ascii_lowercase())
                {
                    // `/`, `?` and the like are typed the same way in every layout.
                    assert!(!q.is_ascii_alphabetic(), "letter `{q}` has no layout key");
                    continue;
                }
                for layout in 0..2 {
                    let c = typed(*q, layout);
                    // Shift is part of an upper-case letter, a terminal may or may not add it.
                    for extra in [KeyModifiers::NONE, KeyModifiers::SHIFT] {
                        if extra == KeyModifiers::SHIFT && !q.is_ascii_uppercase() {
                            continue;
                        }
                        let key = KeyEvent::new(KeyCode::Char(c), *mods | extra);
                        assert_eq!(
                            map_key(key),
                            Some(b.action),
                            "{:?}: `{c}` on the key of `{q}`",
                            b.action
                        );
                    }
                }
                checked += 1;
            }
        }
        assert!(checked > 20, "{checked}");
    }

    #[test]
    fn the_case_is_kept_and_ctrl_works_in_the_cyrillic_layouts() {
        let k = |c, m| KeyEvent::new(KeyCode::Char(c), m);
        // q and Q are different actions: Quit and QuitAll.
        assert_eq!(map_key(k('\u{439}', N)), Some(Action::Quit));
        assert_eq!(map_key(k('\u{419}', N)), Some(Action::QuitAll));
        assert_eq!(map_key(k('\u{437}', C)), Some(Action::Privacy)); // Ctrl + the P key
        assert_eq!(map_key(k('\u{434}', C)), Some(Action::Redraw)); // Ctrl + the L key
        assert_eq!(map_key(k('\u{456}', N)), Some(Action::Settings)); // Ukrainian i = s
                                                                      // A Cyrillic character on a key without a binding stays unbound.
        assert_eq!(map_key(k('\u{44a}', N)), None);
    }

    #[test]
    fn the_layout_table_is_consistent() {
        let mut seen = Vec::new();
        for (q, ru, uk) in LAYOUT_KEYS {
            assert!(!seen.contains(q), "{q} twice");
            seen.push(*q);
            assert_eq!(qwerty(*ru), *q);
            assert_eq!(qwerty(*uk), *q);
        }
    }
}
