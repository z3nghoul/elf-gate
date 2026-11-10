//! The interface's state: what is selected, which screen and popup are open, the log view.
//! The data (servers, connection, rules, settings) is not owned here: it comes from the
//! background process as a [`View`], and everything the user changes is sent back as a [`Cmd`].

use crate::action::{map_key, Action};
use crate::event::{now_hms, Event, Level, LinkEvent, LogLine};
use crate::model::rule::{builtin_presets, validate, RoutingMode, Rule, RuleKind};
use crate::model::server::{Security, Server, ServerRole, FINGERPRINTS};
use crate::model::subscription::Subscription;
use crate::platform::{self, TunHost};
use crate::proto::{Alert, Ask, Cmd, RuleRef, Traffic, Update, View};
use crate::storage::Config;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::ListState;
mod settings;
pub use settings::SettingId;
use std::collections::VecDeque;
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;

pub use crate::engine::{mode_name, MANUAL_GROUP};
pub use crate::model::rule::TrafficMode as Mode;
pub use crate::proto::{Conn, HealthState};

pub const LOG_CAPACITY: usize = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Servers,
    Details,
    Logs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Main,
    Rules,
    Settings,
    Help,
    LogsFull,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmKind {
    /// Close the interface; the VPN keeps running in the background.
    Quit,
    /// Disconnect and stop the background process.
    QuitAll,
    DeleteServer(u64),
    DeleteGroup(String),
    /// A question from the background process.
    Ask(Ask),
}

/// What a text input popup is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputPurpose {
    /// A share link (or subscription URL).
    Link,
    /// The value of a new routing rule.
    Rule(RuleKind),
    /// A text or number setting.
    Setting(SettingId),
}

/// What a selection popup applies its choice to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectKind {
    Fingerprint(u64),
    /// Role of the server in the primary + backup scheme.
    Role(u64),
    /// Which kind of rule to add.
    NewRuleKind,
    /// Pick a running program for a process rule.
    RuleProcess,
}

#[derive(Debug, Clone)]
pub enum Popup {
    Select {
        title: String,
        options: Vec<String>,
        selected: usize,
        kind: SelectKind,
    },
    Input {
        title: String,
        buf: String,
        purpose: InputPurpose,
    },
    Confirm {
        text: String,
        kind: ConfirmKind,
    },
    Error(String),
    /// Information the user should read but that is not a failure.
    Notice(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Row {
    Group(usize),
    Server(usize, usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleItem {
    Preset(String),
    Rule(usize),
}

/// State of the connection to the background process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkState {
    Connecting,
    Up,
    /// The background process is unreachable; the text says why. The interface keeps retrying.
    Down(String),
}

pub struct AppState {
    // ---- mirror of the background process's view ----
    pub subs: Vec<Subscription>,
    pub mode: Mode,
    pub conn: Conn,
    pub conn_mode: Mode,
    pub tun_active: bool,
    pub proxy_active: bool,
    pub health: HealthState,
    pub config: Config,
    pub traffic: Traffic,
    pub tray: bool,
    pub autostart: bool,
    /// Demo data and fake numbers are enabled (debug builds with `ELF_GATE_DEMO=1`).
    pub mock: bool,
    // ---- interface-only state ----
    pub selected: usize,
    pub list_state: ListState,
    pub focus: Focus,
    pub screen: Screen,
    pub popup: Option<Popup>,
    pub filter: String,
    pub filtering: bool,
    pub logs: VecDeque<LogLine>,
    /// Lines scrolled up from the bottom; 0 means "follow new lines".
    pub log_scroll: usize,
    /// Height of the log viewport at the last render (for paging and clamping).
    pub log_view_h: usize,
    pub status: Option<String>,
    pub should_quit: bool,
    pub rules_cursor: usize,
    pub settings_cursor: usize,
    pub link: LinkState,
    /// Servers are listed by ping instead of in their own order.
    pub sorted_by_ping: bool,
    pending_alerts: VecDeque<Alert>,
    /// After the next view the rules cursor goes to the last item (a rule was just added).
    cursor_to_end: bool,
    got_view: bool,
    tun_host: Arc<dyn TunHost>,
    cmd_tx: UnboundedSender<Cmd>,
}

impl AppState {
    pub fn new(cmd_tx: UnboundedSender<Cmd>) -> Self {
        Self {
            subs: Vec::new(),
            mode: Mode::Proxy,
            conn: Conn::Disconnected,
            conn_mode: Mode::Proxy,
            tun_active: false,
            proxy_active: false,
            health: HealthState::Unknown,
            config: Config::default(),
            traffic: Traffic::default(),
            tray: false,
            autostart: false,
            mock: false,
            selected: 0,
            list_state: ListState::default(),
            focus: Focus::Servers,
            screen: Screen::Main,
            popup: None,
            filter: String::new(),
            filtering: false,
            logs: VecDeque::with_capacity(LOG_CAPACITY),
            log_scroll: 0,
            log_view_h: 10,
            status: None,
            should_quit: false,
            rules_cursor: 0,
            settings_cursor: 0,
            link: LinkState::Connecting,
            sorted_by_ping: false,
            pending_alerts: VecDeque::new(),
            cursor_to_end: false,
            got_view: false,
            tun_host: Arc::from(platform::tun_host()),
            cmd_tx,
        }
    }

    #[cfg(test)]
    pub fn with_tun_host(mut self, host: Arc<dyn TunHost>) -> Self {
        self.tun_host = host;
        self
    }

    /// Demo data for the screens (tests and `ELF_GATE_DEMO` debug runs).
    #[cfg(test)]
    pub fn with_demo(cmd_tx: UnboundedSender<Cmd>) -> Self {
        let mut app = Self::new(cmd_tx);
        let mut next_id = 0;
        let view = View {
            groups: crate::mock::subscriptions(&mut next_id),
            conn: Conn::Disconnected,
            mode: Mode::Proxy,
            conn_mode: Mode::Proxy,
            tun_active: false,
            proxy_active: false,
            health: HealthState::Unknown,
            config: Config::default(),
            traffic: Traffic::default(),
            tray: false,
            autostart: false,
            mock: true,
            pid: 0,
        };
        app.apply_view(view);
        app.link = LinkState::Up;
        app
    }

    fn send(&self, cmd: Cmd) {
        let _ = self.cmd_tx.send(cmd);
    }

    // ---------- the link to the background process ----------

    pub fn on_link(&mut self, ev: LinkEvent) {
        match ev {
            LinkEvent::Up => self.link = LinkState::Up,
            LinkEvent::Down(why) => {
                self.link = LinkState::Down(why);
            }
            LinkEvent::Update(update) => self.on_update(update),
        }
    }

    fn on_update(&mut self, update: Update) {
        match update {
            Update::Hello { .. } => {}
            Update::View(view) => self.apply_view(*view),
            Update::Backlog(lines) => {
                self.logs.clear();
                for l in lines {
                    self.push_log(l);
                }
            }
            Update::Log(line) => self.push_log(line),
            Update::Alert(a) => {
                self.pending_alerts.push_back(a);
                self.show_next_alert();
            }
            Update::Status(s) => self.status = Some(s),
            Update::Bye => {
                self.link = LinkState::Down("фоновая часть остановлена".into());
            }
        }
    }

    pub(crate) fn apply_view(&mut self, view: View) {
        let View {
            groups,
            conn,
            mode,
            conn_mode,
            tun_active,
            proxy_active,
            health,
            config,
            traffic,
            tray,
            autostart,
            mock,
            ..
        } = view;
        let collapsed: Vec<String> = self
            .subs
            .iter()
            .filter(|s| s.collapsed)
            .map(|s| s.name.clone())
            .collect();
        self.subs = groups;
        for sub in &mut self.subs {
            sub.collapsed = collapsed.contains(&sub.name);
        }
        self.conn = conn;
        self.mode = mode;
        self.conn_mode = conn_mode;
        self.tun_active = tun_active;
        self.proxy_active = proxy_active;
        self.health = health;
        self.config = config;
        self.traffic = traffic;
        self.tray = tray;
        self.autostart = autostart;
        self.mock = mock;
        self.got_view = true;
        self.clamp_selection();
        let len = self.rule_items().len();
        if self.cursor_to_end {
            self.rules_cursor = len.saturating_sub(1);
            self.cursor_to_end = false;
        } else {
            self.rules_cursor = self.rules_cursor.min(len.saturating_sub(1));
        }
    }

    /// The first view has arrived: the interface shows real data.
    pub fn is_ready(&self) -> bool {
        self.got_view
    }

    fn show_next_alert(&mut self) {
        if self.popup.is_some() {
            return;
        }
        let Some(alert) = self.pending_alerts.pop_front() else {
            return;
        };
        self.popup = Some(match alert {
            Alert::Error(t) => Popup::Error(t),
            Alert::Notice(t) => Popup::Notice(t),
            Alert::Ask { text, ask } => Popup::Confirm {
                text,
                kind: ConfirmKind::Ask(ask),
            },
        });
    }

    // ---------- rows / selection ----------

    /// Indexes of a group's servers in display order.
    fn order_of(&self, group: usize) -> Vec<usize> {
        let sub = &self.subs[group];
        let mut order: Vec<usize> = (0..sub.servers.len()).collect();
        if self.sorted_by_ping {
            order.sort_by_key(|&j| sub.servers[j].ping.sort_key());
        }
        order
    }

    pub fn rows(&self) -> Vec<Row> {
        let needle = self.filter.to_lowercase();
        let mut rows = Vec::new();
        for (i, sub) in self.subs.iter().enumerate() {
            let order = self.order_of(i);
            if needle.is_empty() {
                rows.push(Row::Group(i));
                if !sub.collapsed {
                    rows.extend(order.into_iter().map(|j| Row::Server(i, j)));
                }
            } else {
                let matches: Vec<usize> = order
                    .into_iter()
                    .filter(|&j| sub.servers[j].name.to_lowercase().contains(&needle))
                    .collect();
                if !matches.is_empty() {
                    rows.push(Row::Group(i));
                    rows.extend(matches.into_iter().map(|j| Row::Server(i, j)));
                }
            }
        }
        rows
    }

    pub fn selected_row(&self) -> Option<Row> {
        let rows = self.rows();
        rows.get(self.selected.min(rows.len().saturating_sub(1)))
            .copied()
    }

    pub fn selected_server(&self) -> Option<&Server> {
        match self.selected_row()? {
            Row::Server(i, j) => self.subs.get(i)?.servers.get(j),
            Row::Group(_) => None,
        }
    }

    pub fn server_by_id(&self, id: u64) -> Option<&Server> {
        self.subs
            .iter()
            .flat_map(|s| s.servers.iter())
            .find(|s| s.id == id)
    }

    fn clamp_selection(&mut self) {
        let len = self.rows().len();
        self.selected = self.selected.min(len.saturating_sub(1));
    }

    fn move_selection(&mut self, delta: isize) {
        let len = self.rows().len();
        if len == 0 {
            return;
        }
        self.selected = (self.selected as isize + delta).clamp(0, len as isize - 1) as usize;
    }

    // ---------- logs ----------

    /// A line of the interface's own (not from the background process).
    pub fn log(&mut self, level: Level, text: impl Into<String>) {
        self.push_log(LogLine {
            time: now_hms(),
            level,
            text: text.into(),
        });
    }

    fn push_log(&mut self, line: LogLine) {
        if self.logs.len() == LOG_CAPACITY {
            self.logs.pop_front();
            if self.log_scroll > 0 {
                self.log_scroll = self.log_scroll.saturating_sub(1);
            }
        }
        self.logs.push_back(line);
        // Keep the viewport still while the user reads older lines.
        if self.log_scroll > 0 {
            self.log_scroll += 1;
        }
    }

    fn scroll_logs(&mut self, up: bool, n: usize) {
        let max = self.logs.len().saturating_sub(self.log_view_h);
        self.log_scroll = if up {
            (self.log_scroll + n).min(max)
        } else {
            self.log_scroll.saturating_sub(n)
        };
    }

    // ---------- events ----------

    pub fn handle_event(&mut self, ev: Event) {
        match ev {
            Event::Key(k) => self.handle_key(k),
            Event::Resize | Event::Tick => {}
            Event::Link(l) => self.on_link(l),
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if self.popup.is_some() {
            self.handle_popup_key(key);
            return;
        }
        if self.filtering {
            self.handle_filter_key(key);
            return;
        }
        if let Some(action) = map_key(key) {
            self.handle_action(action);
        }
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.filter.clear();
                self.filtering = false;
            }
            KeyCode::Enter => self.filtering = false,
            KeyCode::Backspace => {
                self.filter.pop();
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.filter.clear();
                self.filtering = false;
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.filter.push(c)
            }
            _ => {}
        }
        self.selected = 0;
        self.clamp_selection();
    }

    fn handle_popup_key(&mut self, key: KeyEvent) {
        let Some(popup) = self.popup.take() else {
            return;
        };
        match popup {
            Popup::Select {
                title,
                options,
                mut selected,
                kind,
            } => {
                match key.code {
                    KeyCode::Esc => {
                        self.show_next_alert();
                        return;
                    }
                    KeyCode::Enter => {
                        let option = options.get(selected).cloned().unwrap_or_default();
                        self.apply_selection(kind, selected, option);
                        self.show_next_alert();
                        return;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        selected = (selected + 1).min(options.len() - 1)
                    }
                    KeyCode::Up | KeyCode::Char('k') => selected = selected.saturating_sub(1),
                    _ => {}
                }
                self.popup = Some(Popup::Select {
                    title,
                    options,
                    selected,
                    kind,
                });
            }
            Popup::Input {
                title,
                mut buf,
                purpose,
            } => match key.code {
                KeyCode::Esc => self.show_next_alert(),
                KeyCode::Enter => {
                    match purpose {
                        InputPurpose::Link => self.submit_input(buf),
                        InputPurpose::Rule(kind) => self.submit_rule(kind, buf),
                        InputPurpose::Setting(id) => self.submit_setting(id, buf),
                    }
                    self.show_next_alert();
                }
                code => {
                    match code {
                        KeyCode::Backspace => {
                            buf.pop();
                        }
                        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                            buf.push(c)
                        }
                        _ => {}
                    }
                    self.popup = Some(Popup::Input {
                        title,
                        buf,
                        purpose,
                    });
                }
            },
            Popup::Confirm { text, kind } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Char('д') | KeyCode::Enter => {
                    self.confirm(kind);
                    self.show_next_alert();
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Char('н') | KeyCode::Esc => {
                    self.decline(kind);
                    self.show_next_alert();
                }
                _ => self.popup = Some(Popup::Confirm { text, kind }),
            },
            Popup::Error(_) | Popup::Notice(_) => self.show_next_alert(),
        }
    }

    // ---------- actions ----------

    pub(crate) fn handle_action(&mut self, action: Action) {
        use Action::*;
        // Server-list actions only make sense on the main screen.
        let on_rules = self.screen == Screen::Rules;
        let main_only = matches!(
            action,
            Enter | Filter | PingAll | SortPing | UpdateSubs | Fingerprint | Role | Fragment
        ) || (matches!(action, Delete | Add) && !on_rules);
        if main_only && self.screen != Screen::Main {
            if action == Enter && self.screen == Screen::Settings {
                self.settings_activate();
            }
            return;
        }
        // These two exist only on the rules screen.
        if matches!(action, Toggle | RoutingMode) && !on_rules {
            return;
        }
        match action {
            Quit => {
                if matches!(self.conn, Conn::Connected(_) | Conn::Connecting(_)) {
                    self.popup = Some(Popup::Confirm {
                        text: "Закрыть интерфейс? Подключение продолжит работать в фоне.\n(Q - выйти и отключить VPN)".into(),
                        kind: ConfirmKind::Quit,
                    });
                } else {
                    self.should_quit = true;
                }
            }
            QuitAll => {
                self.popup = Some(Popup::Confirm {
                    text: "Отключить VPN и остановить фоновую часть?".into(),
                    kind: ConfirmKind::QuitAll,
                });
            }
            Up => self.navigate(-1),
            Down => self.navigate(1),
            PageUp => self.page(true),
            PageDown => self.page(false),
            Top => self.jump(true),
            Bottom => self.jump(false),
            Enter => self.activate_selected(),
            Disconnect => self.send(Cmd::Disconnect),
            ToggleMode => self.send(Cmd::ToggleMode),
            PingAll => {
                self.send(Cmd::PingAll);
            }
            SortPing => {
                self.sorted_by_ping = !self.sorted_by_ping;
                self.selected = 0;
                self.status = Some(
                    if self.sorted_by_ping {
                        "Сортировка по пингу (o - вернуть порядок)"
                    } else {
                        "Исходный порядок серверов"
                    }
                    .into(),
                );
            }
            UpdateSubs => self.send(Cmd::UpdateSubs),
            Add => {
                if self.screen == Screen::Rules {
                    self.rules_add_menu();
                } else {
                    self.popup = Some(Popup::Input {
                        title: "Ссылка на сервер или подписку".into(),
                        buf: String::new(),
                        purpose: InputPurpose::Link,
                    })
                }
            }
            Delete if on_rules => self.rules_delete(),
            Delete => self.ask_delete(),
            Toggle => self.rules_toggle(),
            RoutingMode => self.rules_toggle_routing(),
            Rules => self.toggle_screen(Screen::Rules),
            Settings => self.toggle_screen(Screen::Settings),
            Logs => self.toggle_screen(Screen::LogsFull),
            Help => self.toggle_screen(Screen::Help),
            Filter => self.filtering = true,
            Fingerprint => self.open_fingerprint_menu(),
            Role => self.open_role_menu(),
            Fragment => self.toggle_fragment(),
            Back => self.back(),
            FocusNext => self.cycle_focus(true),
            FocusPrev => self.cycle_focus(false),
            #[cfg(debug_assertions)]
            DebugPanic => panic!("debug panic requested with F12"),
        }
    }

    fn toggle_screen(&mut self, s: Screen) {
        self.screen = if self.screen == s { Screen::Main } else { s };
    }

    fn back(&mut self) {
        if self.screen != Screen::Main {
            self.screen = Screen::Main;
        } else if !self.filter.is_empty() {
            self.filter.clear();
            self.selected = 0;
        } else {
            self.status = None;
        }
    }

    fn cycle_focus(&mut self, forward: bool) {
        if self.screen != Screen::Main {
            return;
        }
        self.focus = match (self.focus, forward) {
            (Focus::Servers, true) | (Focus::Logs, false) => Focus::Details,
            (Focus::Details, true) | (Focus::Servers, false) => Focus::Logs,
            (Focus::Logs, true) | (Focus::Details, false) => Focus::Servers,
        };
    }

    fn logs_active(&self) -> bool {
        self.screen == Screen::LogsFull
            || (self.screen == Screen::Main && self.focus == Focus::Logs)
    }

    fn servers_active(&self) -> bool {
        self.screen == Screen::Main && self.focus == Focus::Servers
    }

    fn navigate(&mut self, delta: isize) {
        if self.screen == Screen::Rules {
            self.rules_move(delta);
        } else if self.screen == Screen::Settings {
            self.settings_move(delta);
        } else if self.logs_active() {
            self.scroll_logs(delta < 0, 1);
        } else if self.servers_active() {
            self.move_selection(delta);
        }
    }

    fn page(&mut self, up: bool) {
        let n = self.log_view_h.max(1);
        if self.logs_active() {
            self.scroll_logs(up, n);
        } else if self.servers_active() {
            self.move_selection(if up { -(n as isize) } else { n as isize });
        }
    }

    fn jump(&mut self, top: bool) {
        if self.logs_active() {
            if top {
                self.scroll_logs(true, usize::MAX / 2);
            } else {
                self.log_scroll = 0;
            }
        } else if self.servers_active() {
            self.selected = if top {
                0
            } else {
                self.rows().len().saturating_sub(1)
            };
        }
    }

    fn activate_selected(&mut self) {
        if !self.servers_active() {
            return;
        }
        match self.selected_row() {
            Some(Row::Group(i)) => self.subs[i].collapsed = !self.subs[i].collapsed,
            Some(Row::Server(..)) => {
                if let Some(s) = self.selected_server() {
                    match &s.unsupported {
                        Some(reason) => {
                            let msg = format!("«{}»: {reason}", s.name);
                            self.popup = Some(if s.info_only {
                                Popup::Notice(msg)
                            } else {
                                Popup::Error(msg)
                            });
                        }
                        None => {
                            let id = s.id;
                            // Enter on the server we are connected to switches it off.
                            if matches!(self.conn, Conn::Connected(c) | Conn::Connecting(c) if c == id)
                            {
                                self.send(Cmd::Disconnect);
                            } else {
                                self.send(Cmd::Connect(id));
                            }
                        }
                    }
                }
            }
            None => {}
        }
        self.clamp_selection();
    }

    fn ask_delete(&mut self) {
        match self.selected_row() {
            Some(Row::Server(..)) => {
                if let Some(s) = self.selected_server() {
                    self.popup = Some(Popup::Confirm {
                        text: format!("Удалить сервер «{}»?", s.name),
                        kind: ConfirmKind::DeleteServer(s.id),
                    });
                }
            }
            Some(Row::Group(i)) => {
                self.popup = Some(Popup::Confirm {
                    text: format!("Удалить «{}» со всеми серверами?", self.subs[i].name),
                    kind: ConfirmKind::DeleteGroup(self.subs[i].name.clone()),
                });
            }
            None => {}
        }
    }

    fn confirm(&mut self, kind: ConfirmKind) {
        match kind {
            ConfirmKind::Quit => self.should_quit = true,
            ConfirmKind::QuitAll => {
                self.send(Cmd::Shutdown);
                self.should_quit = true;
            }
            ConfirmKind::Ask(ask) => self.send(Cmd::Answer { ask, yes: true }),
            ConfirmKind::DeleteServer(id) => self.send(Cmd::DeleteServer(id)),
            ConfirmKind::DeleteGroup(name) => self.send(Cmd::DeleteGroup(name)),
        }
        self.clamp_selection();
    }

    fn decline(&mut self, kind: ConfirmKind) {
        if let ConfirmKind::Ask(ask) = kind {
            self.send(Cmd::Answer { ask, yes: false });
        }
    }

    // ---------- per-server options ----------

    fn open_fingerprint_menu(&mut self) {
        let Some(server) = self.selected_server() else {
            self.status = Some("Выберите сервер (не группу)".into());
            return;
        };
        if server.full.is_some() {
            self.status = Some(
                "У готового конфига провайдера fp не меняется (цепочка переносится как есть)"
                    .into(),
            );
            return;
        }
        if !server.is_supported() || !matches!(server.security, Security::Tls | Security::Reality) {
            self.status = Some("fp применим только к серверам с TLS или Reality".into());
            return;
        }
        let from_link = if server.tls.fingerprint.is_empty() {
            "по умолчанию"
        } else {
            &server.tls.fingerprint
        };
        let mut options = vec![format!("как в ссылке ({from_link})")];
        options.extend(FINGERPRINTS.iter().map(|f| f.to_string()));
        let selected = server
            .fp_override
            .as_deref()
            .and_then(|o| FINGERPRINTS.iter().position(|f| *f == o))
            .map_or(0, |i| i + 1);
        self.popup = Some(Popup::Select {
            title: format!("TLS fingerprint: {}", server.name),
            options,
            selected,
            kind: SelectKind::Fingerprint(server.id),
        });
    }

    fn open_role_menu(&mut self) {
        let Some(server) = self.selected_server() else {
            self.status = Some("Выберите сервер (не группу)".into());
            return;
        };
        if !server.is_supported() || server.full.is_some() {
            self.status = Some(
                "Роль можно назначить только серверу из ссылки (не готовому конфигу провайдера)"
                    .into(),
            );
            return;
        }
        let selected = match server.role {
            None => 0,
            Some(ServerRole::Primary) => 1,
            Some(ServerRole::Backup) => 2,
        };
        self.popup = Some(Popup::Select {
            title: format!("Роль сервера: {}", server.name),
            options: vec![
                "нет".into(),
                "основной (всегда первым)".into(),
                "запасной (если основной недоступен)".into(),
            ],
            selected,
            kind: SelectKind::Role(server.id),
        });
    }

    fn toggle_fragment(&mut self) {
        let Some(server) = self.selected_server() else {
            self.status = Some("Выберите сервер (не группу)".into());
            return;
        };
        if server.full.is_some()
            || !server.is_supported()
            || !matches!(server.security, Security::Tls | Security::Reality)
        {
            self.status =
                Some("Фрагментация применима только к серверам из ссылки с TLS или Reality".into());
            return;
        }
        let (id, on) = (server.id, !server.fragment);
        self.send(Cmd::SetFragment { id, on });
    }

    fn apply_selection(&mut self, kind: SelectKind, index: usize, option: String) {
        match kind {
            SelectKind::Fingerprint(id) => {
                let fp = index
                    .checked_sub(1)
                    .and_then(|i| FINGERPRINTS.get(i))
                    .map(|f| f.to_string());
                self.send(Cmd::SetFingerprint { id, fp });
            }
            SelectKind::Role(id) => {
                let role = match index {
                    1 => Some(ServerRole::Primary),
                    2 => Some(ServerRole::Backup),
                    _ => None,
                };
                self.send(Cmd::SetRole { id, role });
            }
            SelectKind::NewRuleKind => self.rules_kind_chosen(index),
            SelectKind::RuleProcess => self.rules_process_chosen(index, option),
        }
    }

    /// Shown in the details pane when the connection check fails although the server answers
    /// over TCP (the check only starts after a successful TCP probe).
    pub fn fp_hint(&self) -> Option<&'static str> {
        let Conn::Connected(id) = self.conn else {
            return None;
        };
        if !matches!(self.health, HealthState::Failed(_)) {
            return None;
        }
        let server = self.server_by_id(id)?;
        // The link is not shown here, so "has a real fingerprint to change" comes from the kind.
        let fp_matters = matches!(server.security, Security::Tls | Security::Reality)
            && server.unsupported.is_none();
        Some(
            if fp_matters && server.effective_fingerprint() != "firefox" {
                "Сервер доступен, но запрос через него не прошёл. Попробуйте fp=firefox (клавиша f)"
            } else {
                "Сервер доступен, но трафик не проходит. Проверьте ключ, SNI, shortId и порт на сервере"
            },
        )
    }

    /// The connected server (else the selected one) uses `flow=xtls-rprx-vision`, with which Xray
    /// itself refuses UDP/443 (QUIC).
    pub fn vision_in_use(&self) -> bool {
        let server = match self.conn {
            Conn::Connected(id) | Conn::Connecting(id) => self.server_by_id(id),
            _ => self.selected_server(),
        };
        server.is_some_and(|s| s.flow.contains("vision"))
    }

    pub(crate) fn submit_input(&mut self, text: String) {
        let text = text.trim().to_string();
        if text.is_empty() {
            return;
        }
        self.send(Cmd::AddLink(text));
    }

    // ---------- the rules screen ----------

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

    fn rules_move(&mut self, delta: isize) {
        let len = self.rule_items().len() as isize;
        if len > 0 {
            self.rules_cursor = (self.rules_cursor as isize + delta).clamp(0, len - 1) as usize;
        }
    }

    fn rules_toggle(&mut self) {
        match self.current_rule_item() {
            Some(RuleItem::Preset(id)) => self.send(Cmd::ToggleRule(RuleRef::Preset(id))),
            Some(RuleItem::Rule(i)) => self.send(Cmd::ToggleRule(RuleRef::Rule(i))),
            None => {}
        }
    }

    fn rules_delete(&mut self) {
        match self.current_rule_item() {
            Some(RuleItem::Rule(i)) => self.send(Cmd::DeleteRule(i)),
            Some(RuleItem::Preset(_)) => {
                self.status =
                    Some("Встроенный пресет нельзя удалить, его можно выключить (Space)".into());
            }
            None => {}
        }
    }

    fn rules_toggle_routing(&mut self) {
        let next = match self.config.mode.routing {
            RoutingMode::Exclude => RoutingMode::Include,
            RoutingMode::Include => RoutingMode::Exclude,
        };
        self.send(Cmd::SetRouting(next));
    }

    fn rules_add_menu(&mut self) {
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

    fn rules_kind_chosen(&mut self, index: usize) {
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

    fn rules_process_chosen(&mut self, _index: usize, name: String) {
        self.submit_rule(RuleKind::Process, name);
    }

    fn submit_rule(&mut self, kind: RuleKind, text: String) {
        match validate(kind, &text) {
            Ok(value) => {
                if self
                    .config
                    .rules
                    .iter()
                    .any(|r: &Rule| r.kind == kind && r.value == value)
                {
                    self.popup = Some(Popup::Error("Такое правило уже есть".into()));
                    return;
                }
                self.cursor_to_end = true;
                self.send(Cmd::AddRule { kind, value });
            }
            Err(e) => self.popup = Some(Popup::Error(format!("Правило не добавлено: {e}"))),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
