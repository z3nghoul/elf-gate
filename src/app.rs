use crate::action::{map_key, Action};
use crate::build_info;
use crate::event::{now_hms, BgEvent, BgTx, Event, Level, LogLine};
use crate::mock::{self, Lcg};
use crate::model::rule::{builtin_presets, Rule, RuleKind};
use crate::model::server::{Ping, Security, Server, FINGERPRINTS};
use crate::model::subscription::Subscription;
use crate::parser;
use crate::platform::{ProxyAddr, TunHost};
use crate::storage::{Config, ServerEntry, ServerOverride, StateStore, Storage};
use crate::sysproxy::{ProxyCmd, ProxyHandle};
use crate::xray::checkcache::Checker;
use crate::xray::process::Core;
use crate::xray::validate::Verdict;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::ListState;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

mod rules;
mod session;
mod subs;

pub use rules::RuleItem;

pub const LOG_CAPACITY: usize = 2000;
/// Name of the group holding servers added by hand (persisted in `config.toml`).
pub const MANUAL_GROUP: &str = "manual";

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

pub use crate::model::rule::TrafficMode as Mode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conn {
    Disconnected,
    Connecting(u64),
    Connected(u64),
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmKind {
    Quit,
    DeleteServer(u64),
    DeleteGroup(usize),
    /// First TUN start: offer the discord-only preset, then connect to this server.
    PresetOffer(u64),
    /// Windows: restart elf-gate with administrator rights.
    RestartElevated,
    /// Rules changed while connected: restart the core to apply them.
    ApplyRules(u64),
}

/// What a text input popup is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputPurpose {
    /// A share link (or subscription URL).
    Link,
    /// The value of a new routing rule.
    Rule(RuleKind),
}

/// The connection check after the core started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthState {
    Unknown,
    Checking,
    Ok(Duration),
    Failed(String),
}

/// What a selection popup applies its choice to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectKind {
    Fingerprint(u64),
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

pub struct AppState {
    pub subs: Vec<Subscription>,
    pub selected: usize,
    pub list_state: ListState,
    pub focus: Focus,
    pub screen: Screen,
    pub mode: Mode,
    pub conn: Conn,
    pub popup: Option<Popup>,
    pub filter: String,
    pub filtering: bool,
    pub logs: VecDeque<LogLine>,
    /// Lines scrolled up from the bottom; 0 means "follow new lines".
    pub log_scroll: usize,
    /// Height of the log viewport at the last render (for paging and clamping).
    pub log_view_h: usize,
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub status: Option<String>,
    pub should_quit: bool,
    /// Result of the connection check through the local proxy.
    pub health: HealthState,
    /// What the current connection runs in (the mode may be toggled meanwhile).
    pub conn_mode: Mode,
    /// A TUN core is running.
    pub tun_active: bool,
    tun_host: Arc<dyn TunHost>,
    state_store: Option<StateStore>,
    pub rules_cursor: usize,
    pub config: Config,
    storage: Option<Storage>,
    /// The running Xray process, if any.
    core: Option<Core>,
    proxy: Option<ProxyHandle>,
    /// We asked the worker to switch the system proxy on and have not asked to undo it.
    proxy_requested: bool,
    /// The worker reported the system proxy as switched on.
    pub proxy_active: bool,
    /// Demo data and fake numbers are enabled (debug builds).
    pub mock: bool,
    /// A core start or stop is in flight; new connect requests wait for it.
    busy: bool,
    run_dir: PathBuf,
    /// Cached, rate-limited `xray run -test`.
    checker: Arc<Checker>,
    /// Subscriptions being downloaded right now (by name).
    updating: HashSet<String>,
    last_auto_check: Option<Instant>,
    /// When a subscription's update last failed (not retried for ten minutes).
    failed_at: HashMap<String, Instant>,
    next_id: u64,
    tx: BgTx,
    rng: Lcg,
}

impl AppState {
    /// In-memory state with default config and no persistence (tests).
    #[cfg(test)]
    pub fn new(tx: BgTx) -> Self {
        Self::build(tx, Config::default(), None, true)
    }

    pub fn with_config(tx: BgTx, config: Config, storage: Option<Storage>) -> Self {
        Self::build(tx, config, storage, build_info::SHOW_MOCK_DATA)
    }

    /// `mock`: demo servers, fake pings and traffic (debug builds only, see `build_info`).
    pub(crate) fn build(tx: BgTx, config: Config, storage: Option<Storage>, mock: bool) -> Self {
        let mut next_id = 0;
        // Debug builds start with demo groups; real subscriptions come from the cache.
        let mut subs = if mock {
            mock::subscriptions(&mut next_id)
        } else {
            Vec::new()
        };
        let mut load_errors = Vec::new();
        let cache = storage
            .as_ref()
            .map(|st| st.load_subscriptions())
            .unwrap_or_default();
        subs.extend(Self::subscription_groups(
            &config,
            &cache,
            &mut next_id,
            &mut load_errors,
        ));
        let mut manual = Vec::new();
        for entry in &config.servers {
            match parser::parse_link(&entry.link) {
                Ok(mut server) => {
                    next_id += 1;
                    server.id = next_id;
                    manual.push(server);
                }
                Err(e) => load_errors.push(format!("{}: {e}", entry.link)),
            }
        }
        if !manual.is_empty() {
            subs.push(Subscription {
                name: MANUAL_GROUP.into(),
                servers: manual,
                collapsed: false,
                info: None,
                updated: None,
                is_remote: false,
            });
        }
        for sub in &mut subs {
            let group = sub.name.clone();
            for server in &mut sub.servers {
                apply_overrides(&config, &group, server);
            }
        }
        let mut app = Self {
            subs,
            selected: 0,
            list_state: ListState::default(),
            focus: Focus::Servers,
            screen: Screen::Main,
            mode: config.mode.traffic,
            conn: Conn::Disconnected,
            popup: None,
            filter: String::new(),
            filtering: false,
            logs: VecDeque::with_capacity(LOG_CAPACITY),
            log_scroll: 0,
            log_view_h: 10,
            up_bytes: 0,
            down_bytes: 0,
            status: None,
            should_quit: false,
            health: HealthState::Unknown,
            conn_mode: config.mode.traffic,
            tun_active: false,
            tun_host: Arc::from(crate::platform::tun_host()),
            state_store: None,
            rules_cursor: 0,
            config,
            storage,
            core: None,
            proxy: None,
            proxy_requested: false,
            proxy_active: false,
            mock,
            busy: false,
            run_dir: std::env::temp_dir().join("elf-gate-run"),
            checker: Checker::new(None),
            updating: HashSet::new(),
            last_auto_check: None,
            failed_at: HashMap::new(),
            next_id,
            tx,
            rng: Lcg::from_clock(),
        };
        app.log(
            Level::Info,
            if mock {
                "elf-gate started (debug build: subscriptions are mock data)"
            } else {
                "elf-gate started"
            },
        );
        for e in load_errors {
            app.log(Level::Warning, format!("skipped saved server, {e}"));
        }
        app
    }

    /// PID of the running core (tests use it to simulate a crash).
    #[cfg(all(test, unix))]
    pub(crate) fn core_pid(&self) -> Option<u32> {
        self.core.as_ref().and_then(|c| c.pid())
    }

    /// Directory for generated core configs (`run/`).
    pub fn with_run_dir(mut self, dir: PathBuf) -> Self {
        self.run_dir = dir;
        self
    }

    pub fn with_state_store(mut self, store: StateStore) -> Self {
        self.state_store = Some(store);
        self
    }

    /// Keeps `xray run -test` verdicts in `path` between runs.
    pub fn with_check_cache(mut self, path: PathBuf) -> Self {
        self.checker = Checker::new(Some(path));
        self
    }

    #[cfg(test)]
    pub fn with_tun_host(mut self, host: Arc<dyn TunHost>) -> Self {
        self.tun_host = host;
        self
    }

    pub fn with_proxy(mut self, handle: ProxyHandle) -> Self {
        self.proxy = Some(handle);
        self
    }

    /// Restores the system proxy and stops the core before the application exits.
    pub async fn shutdown(&mut self) {
        if let Some(handle) = &self.proxy {
            let controller = handle.controller.clone();
            let _ = tokio::task::spawn_blocking(move || controller.close()).await;
            self.proxy_active = false;
        }
        if let Some(core) = self.core.take() {
            core.stop().await;
            if let Some(store) = &self.state_store {
                crate::tun::mark_down(store);
            }
            self.tun_active = false;
        }
    }

    /// Points the system proxy at the local core, if the user wants that and it can work.
    fn request_proxy_on(&mut self) {
        let Some(handle) = &self.proxy else { return };
        if !self.config.proxy.set_system_proxy
            || self.conn_mode != Mode::Proxy
            || self.proxy_requested
        {
            return;
        }
        let core = &self.config.core;
        if !handle.controller.is_supported() {
            let hint = format!(
                "Системный прокси не поддерживается в этом окружении. Настройте вручную: \
                 SOCKS5 127.0.0.1:{}, HTTP 127.0.0.1:{}. Либо используйте режим TUN (t).",
                core.socks_port, core.http_port
            );
            self.log(Level::Warning, hint.clone());
            self.status = Some(hint);
            return;
        }
        handle.send(ProxyCmd::Enable {
            addr: ProxyAddr {
                host: "127.0.0.1".into(),
                socks_port: core.socks_port,
                http_port: core.http_port,
            },
            bypass: self.config.proxy.bypass.clone(),
        });
        self.proxy_requested = true;
    }

    /// Puts the user's own proxy settings back.
    fn request_proxy_off(&mut self) {
        if self.proxy_requested {
            if let Some(handle) = &self.proxy {
                handle.send(ProxyCmd::Disable);
            }
            self.proxy_requested = false;
        }
    }

    // ---------- rows / selection ----------

    pub fn rows(&self) -> Vec<Row> {
        let needle = self.filter.to_lowercase();
        let mut rows = Vec::new();
        for (i, sub) in self.subs.iter().enumerate() {
            if needle.is_empty() {
                rows.push(Row::Group(i));
                if !sub.collapsed {
                    rows.extend((0..sub.servers.len()).map(|j| Row::Server(i, j)));
                }
            } else {
                let matches: Vec<usize> = sub
                    .servers
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.name.to_lowercase().contains(&needle))
                    .map(|(j, _)| j)
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

    pub fn log(&mut self, level: Level, text: impl Into<String>) {
        let text = text.into();
        // Application lines (never the core's traffic log) also go to the log file,
        // so a tester can attach it to a bug report.
        tracing::info!(target: "app", "{text}");
        self.push_log(LogLine {
            time: now_hms(),
            level,
            text,
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
            Event::Resize => {}
            Event::Tick => self.on_tick(),
            Event::Bg(bg) => self.on_bg(bg),
        }
    }

    fn on_tick(&mut self) {
        self.poll_core();
        self.auto_update_tick();
        if self.mock && matches!(self.conn, Conn::Connected(_)) {
            self.up_bytes += self.rng.next() % 2_000;
            self.down_bytes += self.rng.next() % 20_000;
        }
    }

    fn on_bg(&mut self, ev: BgEvent) {
        match ev {
            BgEvent::Log(line) => self.push_log(line),
            BgEvent::Ping { id, result } => {
                if let Some(s) = self
                    .subs
                    .iter_mut()
                    .flat_map(|s| s.servers.iter_mut())
                    .find(|s| s.id == id)
                {
                    s.ping = result;
                }
            }
            BgEvent::Connected(id) => {
                if self.conn == Conn::Connecting(id) {
                    self.conn = Conn::Connected(id);
                    let name = self.server_by_id(id).map(|s| s.name.clone());
                    self.log(
                        Level::Info,
                        format!("connected to {}", name.unwrap_or_default()),
                    );
                }
            }
            BgEvent::CoreStarted { id, core } => {
                self.busy = false;
                if self.conn == Conn::Connecting(id) {
                    self.on_core_started(id, *core);
                } else {
                    // The user cancelled while the core was starting.
                    self.spawn_stop(*core);
                }
            }
            BgEvent::CoreFailed {
                id,
                error,
                needs_privileges,
            } => {
                self.busy = false;
                self.on_core_failed(id, error, needs_privileges);
            }
            BgEvent::Health { id, result } => self.on_health(id, result),
            BgEvent::CoreStopped => self.busy = false,
            BgEvent::ProxyChanged { active, error } => match error {
                None => {
                    self.proxy_active = active;
                    let msg = if active {
                        "system proxy enabled"
                    } else {
                        "system proxy restored"
                    };
                    self.log(Level::Info, msg);
                }
                Some(e) => {
                    self.proxy_active = false;
                    self.proxy_requested = false;
                    self.log(Level::Error, format!("[Error] system proxy: {e}"));
                    self.popup = Some(Popup::Error(format!("Системный прокси: {e}")));
                }
            },
            BgEvent::ServerRejected { id, reason } => self.mark_rejected(id, &reason),
            BgEvent::ConnectFailed { id, reason } => {
                if self.conn == Conn::Connecting(id) {
                    self.conn = Conn::Error("не удалось подключиться".into());
                    self.log(Level::Error, format!("[Error] {reason}"));
                    self.popup = Some(Popup::Error(reason));
                }
            }
            BgEvent::SubFetched { name, result } => self.on_sub_fetched(name, result),
            BgEvent::SubAdded {
                url,
                user_agent,
                result,
            } => self.on_sub_added(url, user_agent, result),
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
                    KeyCode::Esc => return,
                    KeyCode::Enter => {
                        let option = options.get(selected).cloned().unwrap_or_default();
                        self.apply_selection(kind, selected, option);
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
                KeyCode::Esc => {}
                KeyCode::Enter => match purpose {
                    InputPurpose::Link => self.submit_input(buf),
                    InputPurpose::Rule(kind) => self.submit_rule(kind, buf),
                },
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
                    self.confirm(kind)
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Char('н') | KeyCode::Esc => {
                    self.decline(kind)
                }
                _ => self.popup = Some(Popup::Confirm { text, kind }),
            },
            Popup::Error(_) | Popup::Notice(_) => {}
        }
    }

    // ---------- actions ----------

    pub(crate) fn handle_action(&mut self, action: Action) {
        use Action::*;
        // Server-list actions only make sense on the main screen.
        let on_rules = self.screen == Screen::Rules;
        let main_only = matches!(
            action,
            Enter | Filter | PingAll | SortPing | UpdateSubs | Fingerprint
        ) || (matches!(action, Delete | Add) && !on_rules);
        if main_only && self.screen != Screen::Main {
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
                        text: "Подключение активно. Выйти?".into(),
                        kind: ConfirmKind::Quit,
                    });
                } else {
                    self.should_quit = true;
                }
            }
            Up => self.navigate(-1),
            Down => self.navigate(1),
            PageUp => self.page(true),
            PageDown => self.page(false),
            Top => self.jump(true),
            Bottom => self.jump(false),
            Enter => self.activate_selected(),
            Disconnect => self.disconnect(),
            ToggleMode => self.toggle_mode(),
            PingAll => self.ping_all(),
            SortPing => self.sort_by_ping(),
            UpdateSubs => self.update_subscriptions(),
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
                            self.popup = Some(Popup::Error(msg));
                        }
                        None => {
                            let id = s.id;
                            self.connect(id);
                        }
                    }
                }
            }
            None => {}
        }
        self.clamp_selection();
    }

    // `connect` and `spawn_stop` live in app/session.rs

    fn disconnect(&mut self) {
        if self.conn == Conn::Disconnected {
            return;
        }
        // A core that is still starting is stopped when its start result arrives.
        if let Some(core) = self.core.take() {
            self.spawn_stop(core);
        }
        self.conn = Conn::Disconnected;
        self.log(Level::Info, "disconnected");
        self.request_proxy_off();
    }

    /// Detects a core that died on its own.
    fn poll_core(&mut self) {
        let Some(core) = &mut self.core else { return };
        let Some(info) = core.try_exit() else { return };
        self.core = None;
        self.tun_active = false;
        if let Some(store) = &self.state_store {
            crate::tun::mark_down(store);
        }
        self.request_proxy_off();
        self.conn = Conn::Error("ядро завершилось".into());
        self.log(
            Level::Error,
            format!(
                "[Error] core exited ({}) {}",
                info.code,
                info.tail.replace('\n', " | ")
            ),
        );
        let last: Vec<&str> = info.tail.lines().rev().take(6).collect();
        let last = last.into_iter().rev().collect::<Vec<_>>().join("\n");
        self.popup = Some(Popup::Error(format!(
            "Ядро Xray завершилось ({}).\n\n{last}",
            info.code
        )));
    }

    fn toggle_mode(&mut self) {
        let next = match self.mode {
            Mode::Proxy => Mode::Tun,
            Mode::Tun => Mode::Proxy,
        };
        if next == Mode::Tun && !build_info::TUN_AVAILABLE {
            self.status = Some("Режим TUN в этой версии недоступен".into());
            return;
        }
        self.mode = next;
        self.config.mode.traffic = next;
        self.save_config();
        self.log(Level::Info, format!("mode: {}", mode_name(self.mode)));
        if self.mode == Mode::Tun {
            // TUN needs no system proxy.
            self.request_proxy_off();
        }
        // Switching the mode while connected restarts the connection in the new mode.
        if let Conn::Connected(id) | Conn::Connecting(id) = self.conn {
            self.connect(id);
        }
    }

    fn ping_all(&mut self) {
        if !self.mock {
            self.status = Some("Пинг серверов пока не поддерживается в этой версии".into());
            return;
        }
        for sub in &mut self.subs {
            for s in sub.servers.iter_mut().filter(|s| s.is_supported()) {
                s.ping = Ping::Pending;
                mock::spawn_ping(self.tx.clone(), s.id);
            }
        }
    }

    fn sort_by_ping(&mut self) {
        for sub in &mut self.subs {
            sub.servers.sort_by_key(|s| s.ping.sort_key());
        }
        self.selected = 0;
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
                    kind: ConfirmKind::DeleteGroup(i),
                });
            }
            None => {}
        }
    }

    fn confirm(&mut self, kind: ConfirmKind) {
        match kind {
            ConfirmKind::Quit => self.should_quit = true,
            ConfirmKind::PresetOffer(id) => {
                self.accept_discord_preset();
                self.connect(id);
            }
            ConfirmKind::RestartElevated => self.restart_elevated(),
            ConfirmKind::ApplyRules(id) => self.connect(id),
            ConfirmKind::DeleteServer(id) => {
                self.drop_connection_if(|c| c == id);
                let mut removed_links = Vec::new();
                for sub in &mut self.subs {
                    if sub.name == MANUAL_GROUP {
                        removed_links.extend(
                            sub.servers
                                .iter()
                                .filter(|s| s.id == id)
                                .map(|s| s.link.clone()),
                        );
                    }
                    sub.servers.retain(|s| s.id != id);
                }
                self.subs.retain(|s| !s.servers.is_empty());
                if !removed_links.is_empty() {
                    self.config
                        .servers
                        .retain(|e| !removed_links.contains(&e.link));
                    self.save_config();
                }
            }
            ConfirmKind::DeleteGroup(i) => {
                if i < self.subs.len() {
                    let ids: Vec<u64> = self.subs[i].servers.iter().map(|s| s.id).collect();
                    self.drop_connection_if(|c| ids.contains(&c));
                    let was_manual = self.subs[i].name == MANUAL_GROUP;
                    let name = self.subs[i].name.clone();
                    let was_remote = self.subs[i].is_remote;
                    self.subs.remove(i);
                    if was_manual {
                        self.config.servers.clear();
                        self.save_config();
                    } else if was_remote {
                        self.config.subscriptions.retain(|s| s.name != name);
                        self.save_config();
                        self.save_subscription_cache();
                    }
                }
            }
        }
        self.clamp_selection();
    }

    fn drop_connection_if(&mut self, f: impl Fn(u64) -> bool) {
        if let Conn::Connected(id) | Conn::Connecting(id) = self.conn {
            if f(id) {
                self.disconnect();
            }
        }
    }

    // ---------- TLS fingerprint override ----------

    fn open_fingerprint_menu(&mut self) {
        let Some(server) = self.selected_server() else {
            self.status = Some("Выберите сервер (не группу)".into());
            return;
        };
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

    fn apply_selection(&mut self, kind: SelectKind, index: usize, option: String) {
        match kind {
            SelectKind::Fingerprint(id) => {
                let fp = index
                    .checked_sub(1)
                    .and_then(|i| FINGERPRINTS.get(i))
                    .map(|f| f.to_string());
                self.set_fingerprint(id, fp);
            }
            SelectKind::NewRuleKind => self.rules_kind_chosen(index),
            SelectKind::RuleProcess => self.rules_process_chosen(index, option),
        }
    }

    /// Stores (or clears, with `None`) the fingerprint override and restarts the core if
    /// it is running this server, so the change takes effect at once.
    fn set_fingerprint(&mut self, id: u64, fp: Option<String>) {
        let mut found = None;
        for sub in &mut self.subs {
            let group = sub.name.clone();
            if let Some(server) = sub.servers.iter_mut().find(|s| s.id == id) {
                server.fp_override = fp.clone();
                found = Some((override_key(&group, server), server.name.clone()));
            }
        }
        let Some((key, name)) = found else { return };
        self.update_override(&key, |o| {
            o.fp = fp.clone();
            o.fp_auto = false;
        });
        self.log(
            Level::Info,
            format!(
                "fp for {name}: {}",
                fp.as_deref().unwrap_or("as in the link")
            ),
        );
        self.save_config();
        if matches!(self.conn, Conn::Connected(c) | Conn::Connecting(c) if c == id) {
            if self.busy {
                self.status = Some("fp сохранён, применится при следующем подключении".into());
            } else {
                self.connect(id);
            }
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
        let fp_matters =
            matches!(server.security, Security::Tls | Security::Reality) && !server.link.is_empty();
        Some(
            if fp_matters && server.effective_fingerprint() != "firefox" {
                "Сервер доступен, но запрос через него не прошёл. Попробуйте fp=firefox (клавиша f)"
            } else {
                "Сервер доступен, но трафик не проходит. Проверьте ключ, SNI, shortId и порт на сервере"
            },
        )
    }

    /// Greys the server out and keeps Xray's error text for the details pane.
    fn mark_rejected(&mut self, id: u64, reason: &str) {
        let mut name = None;
        for server in self
            .subs
            .iter_mut()
            .flat_map(|s| s.servers.iter_mut())
            .filter(|s| s.id == id)
        {
            server.unsupported = Some(format!("Xray отверг конфиг: {reason}"));
            name = Some(server.name.clone());
        }
        if let Some(name) = name {
            self.log(
                Level::Warning,
                format!("[Warning] {name}: Xray отверг конфиг: {reason}"),
            );
        }
    }

    /// Checks the given servers with `xray run -test` in the background (at most four
    /// processes at once, verdicts come from the cache when the config was seen before).
    fn spawn_checks(&self, servers: Vec<Server>) {
        if servers.is_empty() {
            return;
        }
        let tx = self.tx.clone();
        let core_cfg = self.config.core.clone();
        let run_dir = self.run_dir.clone();
        let checker = self.checker.clone();
        tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            for server in servers {
                let (tx, core_cfg, run_dir, checker) = (
                    tx.clone(),
                    core_cfg.clone(),
                    run_dir.clone(),
                    checker.clone(),
                );
                tasks.spawn(async move {
                    match checker.check(&core_cfg, &server, &run_dir).await {
                        Verdict::Accepted => {}
                        Verdict::Rejected(reason) => {
                            let _ = tx.send(BgEvent::ServerRejected {
                                id: server.id,
                                reason,
                            });
                        }
                        Verdict::Unavailable(why) => {
                            // Not Xray's verdict on the server (e.g. no binary yet): say so once.
                            if checker.first_unavailable() {
                                let _ = tx.send(BgEvent::Log(LogLine {
                                    time: now_hms(),
                                    level: Level::Info,
                                    text: format!("server validation skipped: {why}"),
                                }));
                            }
                        }
                    }
                });
            }
            while tasks.join_next().await.is_some() {}
            checker.flush();
        });
    }

    /// Validates every imported server that has a real link. Call once after the
    /// run directory is set.
    pub fn start_background_checks(&self) {
        let servers: Vec<Server> = self
            .subs
            .iter()
            .flat_map(|s| s.servers.iter())
            .filter(|s| !s.link.is_empty() && s.is_supported())
            .cloned()
            .collect();
        self.spawn_checks(servers);
    }

    pub(crate) fn submit_input(&mut self, text: String) {
        let text = text.trim().to_string();
        if text.starts_with("http://") || text.starts_with("https://") {
            self.add_subscription_url(text);
            return;
        }
        match parser::parse_link(&text) {
            Ok(server) => self.add_manual_server(server),
            Err(e) => {
                self.log(Level::Warning, format!("bad link: {e}"));
                self.popup = Some(Popup::Error(e.to_string()));
            }
        }
    }

    fn add_manual_server(&mut self, mut server: Server) {
        if self.config.servers.iter().any(|e| e.link == server.link) {
            self.popup = Some(Popup::Error("Этот сервер уже добавлен".into()));
            return;
        }
        self.next_id += 1;
        server.id = self.next_id;
        apply_overrides(&self.config, MANUAL_GROUP, &mut server);
        self.config.servers.push(ServerEntry {
            link: server.link.clone(),
        });
        let name = server.name.clone();
        if server.is_supported() {
            self.spawn_checks(vec![server.clone()]);
        }
        match self.subs.iter_mut().find(|s| s.name == MANUAL_GROUP) {
            Some(sub) => sub.servers.push(server),
            None => self.subs.push(Subscription {
                name: MANUAL_GROUP.into(),
                servers: vec![server],
                collapsed: false,
                info: None,
                updated: None,
                is_remote: false,
            }),
        }
        self.log(Level::Info, format!("added server {name}"));
        self.status = Some(format!("Добавлен: {name}"));
        self.save_config();
    }

    /// Edits (creating if needed) the `[[overrides]]` entry for `key`; an entry that no longer
    /// overrides anything is removed.
    fn update_override(&mut self, key: &str, edit: impl FnOnce(&mut ServerOverride)) {
        let pos = self.config.overrides.iter().position(|o| o.server == key);
        let mut entry = match pos {
            Some(i) => self.config.overrides.remove(i),
            None => ServerOverride::new(key.to_string()),
        };
        edit(&mut entry);
        if !entry.is_empty() {
            match pos {
                Some(i) => self.config.overrides.insert(i, entry),
                None => self.config.overrides.push(entry),
            }
        }
    }

    fn save_config(&mut self) {
        let Some(storage) = &self.storage else { return };
        if let Err(e) = storage.save(&self.config) {
            self.log(Level::Error, format!("[Error] {e}"));
            self.popup = Some(Popup::Error(e.to_string()));
        }
    }
}

/// Stable identity of a server for per-server overrides: `"<group>/<name>|<host>:<port>"`.
pub fn override_key(group: &str, server: &Server) -> String {
    format!("{group}/{}|{}:{}", server.name, server.address, server.port)
}

/// Copies the per-server settings from `[[overrides]]` onto a freshly created server.
pub(crate) fn apply_overrides(config: &Config, group: &str, server: &mut Server) {
    let key = override_key(group, server);
    let found = config.overrides.iter().find(|o| o.server == key);
    server.fp_override = found.and_then(|o| o.fp.clone());
    server.fp_auto = found.is_some_and(|o| o.fp_auto);
    server.fragment = found.is_some_and(|o| o.fragment);
    server.role = found.and_then(|o| o.role);
}

pub fn mode_name(m: Mode) -> &'static str {
    match m {
        Mode::Proxy => "PROXY",
        Mode::Tun => "TUN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::unbounded_channel;

    fn app() -> AppState {
        let (tx, _rx) = unbounded_channel();
        AppState::new(tx)
    }

    #[tokio::test]
    async fn filter_shows_only_matches() {
        let mut a = app();
        a.filter = "de-".into();
        let rows = a.rows();
        assert_eq!(rows.len(), 2); // group + DE-1
        assert!(matches!(rows[1], Row::Server(0, 0)));
    }

    #[tokio::test]
    async fn collapsing_hides_servers() {
        let mut a = app();
        let all = a.rows().len();
        a.subs[0].collapsed = true;
        assert_eq!(a.rows().len(), all - a.subs[0].servers.len());
    }

    #[tokio::test]
    async fn log_buffer_is_bounded() {
        let mut a = app();
        for i in 0..LOG_CAPACITY + 50 {
            a.log(Level::Info, format!("line {i}"));
        }
        assert_eq!(a.logs.len(), LOG_CAPACITY);
    }

    #[tokio::test]
    async fn quit_asks_when_connected() {
        let mut a = app();
        a.conn = Conn::Connected(1);
        a.handle_action(Action::Quit);
        assert!(!a.should_quit);
        assert!(matches!(a.popup, Some(Popup::Confirm { .. })));
    }

    #[tokio::test]
    async fn quit_is_immediate_when_disconnected() {
        let mut a = app();
        a.handle_action(Action::Quit);
        assert!(a.should_quit);
    }

    #[tokio::test]
    async fn adding_a_link_adds_to_manual_group_and_config() {
        let mut a = app();
        let before = a.rows().len();
        a.submit_input("vless://u@h.example.com:443?type=tcp#Mine".into());
        assert!(a.popup.is_none());
        assert_eq!(a.config.servers.len(), 1);
        assert_eq!(a.rows().len(), before + 2); // new group header + server
        assert_eq!(a.subs.last().unwrap().name, MANUAL_GROUP);
    }

    #[tokio::test]
    async fn bad_link_shows_error_and_changes_nothing() {
        let mut a = app();
        let before = a.rows().len();
        a.submit_input("garbage".into());
        assert!(matches!(a.popup, Some(Popup::Error(_))));
        assert_eq!(a.rows().len(), before);
        assert!(a.config.servers.is_empty());
    }

    #[tokio::test]
    async fn duplicate_link_is_rejected() {
        let mut a = app();
        a.submit_input("vless://u@h:443#A".into());
        a.submit_input("vless://u@h:443#A".into());
        assert!(matches!(a.popup, Some(Popup::Error(_))));
        assert_eq!(a.config.servers.len(), 1);
    }

    #[tokio::test]
    async fn manual_servers_survive_restart() {
        let dir = std::env::temp_dir().join(format!("elf-gate-app-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = Storage::new(&dir);
        let (tx, _rx) = unbounded_channel();
        let mut a = AppState::with_config(tx, Config::default(), Some(storage.clone()));
        a.submit_input("vless://u@h.example.com:443?security=tls#Saved".into());
        a.submit_input("trojan://p@h:443#Grey".into());

        let (tx, _rx) = unbounded_channel();
        let b = AppState::with_config(tx, storage.load().unwrap(), Some(storage));
        let manual = b.subs.iter().find(|s| s.name == MANUAL_GROUP).unwrap();
        assert_eq!(manual.servers.len(), 2);
        assert_eq!(manual.servers[0].name, "Saved");
        assert!(!manual.servers[1].is_supported());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn deleting_a_manual_server_updates_config() {
        let mut a = app();
        a.submit_input("vless://u@h:443#A".into());
        let id = a.subs.last().unwrap().servers[0].id;
        a.confirm(ConfirmKind::DeleteServer(id));
        assert!(a.config.servers.is_empty());
        assert!(a.subs.iter().all(|s| s.name != MANUAL_GROUP));
    }

    #[tokio::test]
    async fn xray_rejection_greys_the_server_out_with_xrays_text() {
        let mut a = app();
        a.submit_input("vless://u@example.com:443?security=none#Dom".into());
        let id = a.subs.last().unwrap().servers[0].id;
        assert!(a.server_by_id(id).unwrap().is_supported());
        a.on_bg(BgEvent::ServerRejected {
            id,
            reason: "vless without TLS is prohibited".into(),
        });
        let s = a.server_by_id(id).unwrap();
        assert!(!s.is_supported());
        assert!(s
            .unsupported
            .as_ref()
            .unwrap()
            .contains("vless without TLS is prohibited"));
    }

    #[tokio::test]
    async fn greyed_out_server_cannot_be_connected() {
        let mut a = app();
        a.submit_input("vless://u@8.8.8.8:443?security=none#Pub".into());
        a.selected = a.rows().len() - 1; // the manual server
        a.activate_selected();
        assert!(matches!(a.popup, Some(Popup::Error(_))));
        assert_eq!(a.conn, Conn::Disconnected);
    }

    const REALITY: &str =
        "vless://u@h.example.com:443?security=reality&sni=x.org&pbk=K&sid=ab&fp=chrome#R1";

    fn app_with_reality() -> (AppState, u64) {
        let mut a = app();
        a.submit_input(REALITY.into());
        a.selected = a.rows().len() - 1;
        let id = a.selected_server().unwrap().id;
        (a, id)
    }

    fn press(a: &mut AppState, code: KeyCode) {
        a.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    #[tokio::test]
    async fn fingerprint_menu_stores_a_per_server_override() {
        let (mut a, id) = app_with_reality();
        a.handle_action(Action::Fingerprint);
        let Some(Popup::Select {
            options, selected, ..
        }) = &a.popup
        else {
            panic!("menu expected, got {:?}", a.popup)
        };
        assert_eq!(options[0], "как в ссылке (chrome)");
        assert_eq!(&options[1..], FINGERPRINTS);
        assert_eq!(*selected, 0);

        press(&mut a, KeyCode::Down); // chrome
        press(&mut a, KeyCode::Down); // firefox
        press(&mut a, KeyCode::Enter);
        assert!(a.popup.is_none());
        let s = a.server_by_id(id).unwrap();
        assert_eq!(s.fp_override.as_deref(), Some("firefox"));
        assert_eq!(
            s.tls.fingerprint, "chrome",
            "the link's fp is never rewritten"
        );
        assert_eq!(a.config.overrides.len(), 1);
        assert_eq!(a.config.overrides[0].server, "manual/R1|h.example.com:443");
        assert_eq!(
            a.config.servers[0].link, REALITY,
            "the stored link is untouched"
        );

        // The menu opens on the current choice; picking the first entry clears the override.
        a.handle_action(Action::Fingerprint);
        assert!(matches!(a.popup, Some(Popup::Select { selected: 2, .. })));
        press(&mut a, KeyCode::Up);
        press(&mut a, KeyCode::Up);
        press(&mut a, KeyCode::Enter);
        assert_eq!(a.server_by_id(id).unwrap().fp_override, None);
        assert!(a.config.overrides.is_empty());
    }

    #[tokio::test]
    async fn escape_leaves_the_fingerprint_unchanged() {
        let (mut a, id) = app_with_reality();
        a.handle_action(Action::Fingerprint);
        press(&mut a, KeyCode::Down);
        press(&mut a, KeyCode::Esc);
        assert!(a.popup.is_none());
        assert_eq!(a.server_by_id(id).unwrap().fp_override, None);
    }

    #[tokio::test]
    async fn fingerprint_override_survives_restart() {
        let dir = std::env::temp_dir().join(format!("elf-gate-fp-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = Storage::new(&dir);
        let (tx, _rx) = unbounded_channel();
        let mut a = AppState::with_config(tx, Config::default(), Some(storage.clone()));
        a.submit_input(REALITY.into());
        a.selected = a.rows().len() - 1;
        let id = a.selected_server().unwrap().id;
        a.set_fingerprint(id, Some("safari".into()));

        let text = std::fs::read_to_string(dir.join("config.toml")).unwrap();
        assert!(
            text.contains("[[overrides]]") && text.contains("fp = \"safari\""),
            "{text}"
        );

        let (tx, _rx) = unbounded_channel();
        let b = AppState::with_config(tx, storage.load().unwrap(), Some(storage));
        let manual = b.subs.iter().find(|s| s.name == MANUAL_GROUP).unwrap();
        assert_eq!(manual.servers[0].fp_override.as_deref(), Some("safari"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn fingerprint_menu_is_for_tls_and_reality_only() {
        let mut a = app();
        a.submit_input("vless://u@10.0.0.5:443?security=none#Plain".into());
        a.selected = a.rows().len() - 1;
        a.handle_action(Action::Fingerprint);
        assert!(a.popup.is_none());
        assert!(a.status.as_deref().unwrap().contains("TLS или Reality"));
    }

    fn release_app() -> AppState {
        let (tx, _rx) = unbounded_channel();
        AppState::build(tx, Config::default(), None, false)
    }

    #[tokio::test]
    async fn release_build_starts_with_an_empty_server_list() {
        let a = release_app();
        assert!(a.subs.is_empty(), "no mock servers in a release build");
        assert!(a.rows().is_empty());
        assert_eq!(a.logs.len(), 1);
        assert_eq!(a.logs[0].text, "elf-gate started");
    }

    #[tokio::test]
    async fn release_build_has_no_fake_traffic_pings_or_subscriptions() {
        let mut a = release_app();
        a.submit_input("vless://u@10.0.0.5:443?security=none#Real".into());
        a.conn = Conn::Connected(1);
        for _ in 0..10 {
            a.on_tick();
        }
        assert_eq!((a.up_bytes, a.down_bytes), (0, 0));

        a.handle_action(Action::PingAll);
        assert!(a.status.as_deref().unwrap().contains("Пинг"));
        assert_eq!(a.subs[0].servers[0].ping, Ping::Unknown);

        a.handle_action(Action::UpdateSubs);
        assert!(a.status.as_deref().unwrap().contains("Нет подписок"));
        assert!(a.updating.is_empty());

        let groups = a.subs.len();
        // A URL starts a real download (not a mock group); nothing appears until it succeeds.
        a.submit_input("https://127.0.0.1:1/sub".into());
        assert_eq!(a.subs.len(), groups, "no mock subscription may appear");
    }
}
