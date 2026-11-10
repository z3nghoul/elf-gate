//! The rules screen: routing mode, presets, the user's own rules, the process picker.

use super::*;
use crate::model::rule::{validate, RoutingMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleItem {
    Preset(String),
    Rule(usize),
}

impl AppState {
    /// Presets first, then the user's rules, in the order the screen lists them.
    pub fn rule_items(&self) -> Vec<RuleItem> {
        builtin_presets()
            .into_iter()
            .map(|p| RuleItem::Preset(p.id))
            .chain((0..self.config.rules.len()).map(RuleItem::Rule))
            .collect()
    }

    fn current_rule_item(&self) -> Option<RuleItem> {
        let items = self.rule_items();
        items
            .get(self.rules_cursor.min(items.len().saturating_sub(1)))
            .cloned()
    }

    pub(super) fn rules_move(&mut self, delta: isize) {
        let len = self.rule_items().len() as isize;
        if len > 0 {
            self.rules_cursor = (self.rules_cursor as isize + delta).clamp(0, len - 1) as usize;
        }
    }

    pub(super) fn rules_toggle(&mut self) {
        match self.current_rule_item() {
            Some(RuleItem::Preset(id)) => {
                let list = &mut self.config.presets.enabled;
                if let Some(pos) = list.iter().position(|p| *p == id) {
                    list.remove(pos);
                } else {
                    list.push(id);
                }
            }
            Some(RuleItem::Rule(i)) => {
                if let Some(rule) = self.config.rules.get_mut(i) {
                    rule.enabled = !rule.enabled;
                }
            }
            None => return,
        }
        self.rules_changed();
    }

    pub(super) fn rules_delete(&mut self) {
        match self.current_rule_item() {
            Some(RuleItem::Rule(i)) => {
                self.config.rules.remove(i);
                let len = self.rule_items().len();
                self.rules_cursor = self.rules_cursor.min(len.saturating_sub(1));
                self.rules_changed();
            }
            Some(RuleItem::Preset(_)) => {
                self.status =
                    Some("Встроенный пресет нельзя удалить, его можно выключить (Space)".into());
            }
            None => {}
        }
    }

    pub(super) fn rules_toggle_routing(&mut self) {
        self.config.mode.routing = match self.config.mode.routing {
            RoutingMode::Exclude => RoutingMode::Include,
            RoutingMode::Include => RoutingMode::Exclude,
        };
        self.rules_changed();
    }

    pub(super) fn rules_add_menu(&mut self) {
        self.popup = Some(Popup::Select {
            title: "Новое правило".into(),
            options: vec![
                "Процесс: выбрать из запущенных".into(),
                "Процесс: ввести имя".into(),
                "Домен".into(),
                "IP-адрес или сеть (CIDR)".into(),
                "Набор geosite".into(),
                "Набор geoip".into(),
            ],
            selected: 0,
            kind: SelectKind::NewRuleKind,
        });
    }

    pub(super) fn rules_kind_chosen(&mut self, index: usize) {
        let kind = match index {
            0 => {
                let names = self.tun_host.running_processes();
                if names.is_empty() {
                    self.popup = Some(Popup::Notice(
                        "Не удалось получить список запущенных программ. Введите имя вручную."
                            .into(),
                    ));
                } else {
                    self.popup = Some(Popup::Select {
                        title: "Запущенные программы (имя файла, как его видит ядро)".into(),
                        options: names,
                        selected: 0,
                        kind: SelectKind::RuleProcess,
                    });
                }
                return;
            }
            1 => RuleKind::Process,
            2 => RuleKind::Domain,
            3 => RuleKind::Ip,
            4 => RuleKind::Geosite,
            _ => RuleKind::Geoip,
        };
        let hint = match kind {
            RuleKind::Process => "Имя процесса (Discord, steam), регистр важен",
            RuleKind::Domain => "Домен (example.com, с поддоменами)",
            RuleKind::Ip => "IP или сеть (10.0.0.0/8)",
            RuleKind::Geosite => "Набор geosite (category-ru)",
            RuleKind::Geoip => "Набор geoip (ru)",
        };
        self.popup = Some(Popup::Input {
            title: hint.into(),
            buf: String::new(),
            purpose: InputPurpose::Rule(kind),
        });
    }

    pub(super) fn rules_process_chosen(&mut self, _index: usize, name: String) {
        self.add_rule(RuleKind::Process, name);
    }

    pub(super) fn submit_rule(&mut self, kind: RuleKind, text: String) {
        match validate(kind, &text) {
            Ok(value) => self.add_rule(kind, value),
            Err(e) => self.popup = Some(Popup::Error(format!("Правило не добавлено: {e}"))),
        }
    }

    fn add_rule(&mut self, kind: RuleKind, value: String) {
        if self
            .config
            .rules
            .iter()
            .any(|r| r.kind == kind && r.value == value)
        {
            self.popup = Some(Popup::Error("Такое правило уже есть".into()));
            return;
        }
        self.config.rules.push(Rule::new(kind, value));
        self.rules_cursor = self.rule_items().len() - 1;
        self.rules_changed();
    }

    /// Saves, and offers to restart the core when it is running.
    fn rules_changed(&mut self) {
        self.save_config();
        if let (Conn::Connected(id), Some(_)) = (&self.conn, &self.core) {
            let id = *id;
            if self.popup.is_none() {
                self.popup = Some(Popup::Confirm {
                    text: "Правила изменены. Перезапустить ядро, чтобы применить?".into(),
                    kind: ConfirmKind::ApplyRules(id),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::mock::MockTunHost;
    use tokio::sync::mpsc::unbounded_channel;

    fn app(dir: &std::path::Path) -> AppState {
        let (tx, _rx) = unbounded_channel();
        let mut a = AppState::build(tx, Config::default(), Some(Storage::new(dir)), false)
            .with_tun_host(Arc::new(MockTunHost::healthy()));
        a.screen = Screen::Rules;
        a
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("elf-gate-rules-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn press(a: &mut AppState, code: KeyCode) {
        a.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    #[tokio::test]
    async fn presets_are_listed_first_then_user_rules() {
        let dir = temp_dir("list");
        let mut a = app(&dir);
        a.config.rules.push(Rule::new(RuleKind::Process, "obs"));
        let items = a.rule_items();
        assert_eq!(items.len(), builtin_presets().len() + 1);
        assert!(matches!(items[0], RuleItem::Preset(_)));
        assert_eq!(items.last(), Some(&RuleItem::Rule(0)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn space_toggles_presets_and_rules_and_saves() {
        let dir = temp_dir("toggle");
        let mut a = app(&dir);
        let discord = a
            .rule_items()
            .iter()
            .position(|i| *i == RuleItem::Preset("discord-only".into()))
            .unwrap();
        a.rules_cursor = discord;
        a.handle_action(Action::Toggle);
        assert!(a
            .config
            .presets
            .enabled
            .contains(&"discord-only".to_string()));
        assert!(Storage::new(&dir)
            .load()
            .unwrap()
            .presets
            .enabled
            .contains(&"discord-only".to_string()));
        a.handle_action(Action::Toggle);
        assert!(!a
            .config
            .presets
            .enabled
            .contains(&"discord-only".to_string()));

        a.config
            .rules
            .push(Rule::new(RuleKind::Domain, "example.com"));
        a.rules_cursor = a.rule_items().len() - 1;
        a.handle_action(Action::Toggle);
        assert!(!a.config.rules[0].enabled);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn m_switches_the_routing_mode() {
        let dir = temp_dir("mode");
        let mut a = app(&dir);
        assert_eq!(a.config.mode.routing, RoutingMode::Exclude);
        a.handle_action(Action::RoutingMode);
        assert_eq!(a.config.mode.routing, RoutingMode::Include);
        assert_eq!(
            Storage::new(&dir).load().unwrap().mode.routing,
            RoutingMode::Include
        );
        // Only on the rules screen.
        a.screen = Screen::Main;
        a.handle_action(Action::RoutingMode);
        assert_eq!(a.config.mode.routing, RoutingMode::Include);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn adding_rules_by_typing_validates_the_input() {
        let dir = temp_dir("add");
        let mut a = app(&dir);
        a.handle_action(Action::Add);
        assert!(matches!(
            a.popup,
            Some(Popup::Select {
                kind: SelectKind::NewRuleKind,
                ..
            })
        ));

        // Menu entry 2 = domain; type a value; Enter.
        press(&mut a, KeyCode::Down);
        press(&mut a, KeyCode::Down);
        press(&mut a, KeyCode::Enter);
        assert!(matches!(
            a.popup,
            Some(Popup::Input {
                purpose: InputPurpose::Rule(RuleKind::Domain),
                ..
            })
        ));
        for c in "Discord.com".chars() {
            press(&mut a, KeyCode::Char(c));
        }
        press(&mut a, KeyCode::Enter);
        assert!(a.popup.is_none());
        assert_eq!(
            a.config.rules,
            vec![Rule::new(RuleKind::Domain, "discord.com")]
        );

        // Bad input is refused with the reason; duplicates too.
        a.submit_rule(RuleKind::Ip, "10.0.0.0/40".into());
        assert!(matches!(&a.popup, Some(Popup::Error(t)) if t.contains("префикса")));
        a.popup = None;
        a.submit_rule(RuleKind::Domain, "discord.com".into());
        assert!(matches!(&a.popup, Some(Popup::Error(t)) if t.contains("уже есть")));
        assert_eq!(a.config.rules.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn the_process_picker_lists_running_programs() {
        let dir = temp_dir("picker");
        let mut a = app(&dir);
        a.handle_action(Action::Add);
        press(&mut a, KeyCode::Enter); // first entry: pick from running programs
        let Some(Popup::Select { options, kind, .. }) = &a.popup else {
            panic!("{:?}", a.popup)
        };
        assert_eq!(*kind, SelectKind::RuleProcess);
        assert_eq!(options, &vec!["Discord".to_string(), "firefox".to_string()]);
        press(&mut a, KeyCode::Down);
        press(&mut a, KeyCode::Enter);
        assert_eq!(
            a.config.rules,
            vec![Rule::new(RuleKind::Process, "firefox")]
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn deleting_works_for_user_rules_only() {
        let dir = temp_dir("delete");
        let mut a = app(&dir);
        a.rules_cursor = 0; // a built-in preset
        a.handle_action(Action::Delete);
        assert!(a.status.as_deref().unwrap().contains("нельзя удалить"));

        a.config.rules.push(Rule::new(RuleKind::Process, "obs"));
        a.rules_cursor = a.rule_items().len() - 1;
        a.handle_action(Action::Delete);
        assert!(a.config.rules.is_empty());
        assert_eq!(
            a.rules_cursor,
            a.rule_items().len() - 1,
            "the cursor stays inside the list"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn arrow_keys_move_the_cursor_on_the_rules_screen_only() {
        let dir = temp_dir("move");
        let mut a = app(&dir);
        a.handle_action(Action::Down);
        a.handle_action(Action::Down);
        assert_eq!(a.rules_cursor, 2);
        a.handle_action(Action::Up);
        assert_eq!(a.rules_cursor, 1);
        for _ in 0..100 {
            a.handle_action(Action::Up);
        }
        assert_eq!(a.rules_cursor, 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn rules_screen_renders_modes_and_inactive_notes() {
        let dir = temp_dir("render");
        let mut a = app(&dir);
        a.config.rules.push(Rule::new(RuleKind::Process, "obs"));
        let out = crate::ui::tests_support::draw(100, 30, &mut a);
        assert!(out.contains("Режим маршрутизации: exclude"), "{out}");
        assert!(
            out.contains("правила по процессам неактивны"),
            "proxy mode note: {out}"
        );
        assert!(
            out.contains("Только Discord через VPN")
                && out.contains("(неактивен в режиме exclude)"),
            "{out}"
        );
        assert!(
            out.contains("процесс  obs") && out.contains("(только в TUN)"),
            "{out}"
        );
        assert!(out.contains("Space вкл/выкл"), "{out}");

        a.mode = Mode::Tun;
        a.config.mode.routing = RoutingMode::Include;
        let out = crate::ui::tests_support::draw(100, 30, &mut a);
        assert!(
            out.contains("Режим маршрутизации: include")
                && out.contains("TUN, правила по процессам работают"),
            "{out}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
