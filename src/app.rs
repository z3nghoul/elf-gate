use crate::action::{map_key, Action};
use crate::build_info;
use crate::event::{now_hms, BgEvent, BgTx, Event, Level, LogLine};
use crate::mock::{self, Lcg};
use crate::model::server::{Ping, Security, Server, Transport, FINGERPRINTS};
use crate::model::subscription::Subscription;
use crate::parser;
use crate::platform::ProxyAddr;
use crate::storage::{Config, ServerEntry, ServerOverride, Storage};
use crate::sysproxy::{ProxyCmd, ProxyHandle};
use crate::xray::validate::{self, Verdict};
use crate::xray::{self, process::Core};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::ListState;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Proxy,
    Tun,
}

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
}

/// What a selection popup applies its choice to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectKind {
    Fingerprint(u64),
}

/// Core warnings/errors within this window count as "connections are failing".
const FAILURE_WINDOW: Duration = Duration::from_secs(30);
const FAILURE_THRESHOLD: usize = 3;

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
    },
    Confirm {
        text: String,
        kind: ConfirmKind,
    },
    Error(String),
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
    /// Times of recent core warnings/errors, for the "try fp=firefox" hint.
    core_failures: VecDeque<Instant>,
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
        // Subscriptions are still mock data until stage 6, and only in debug builds.
        let mut subs = if mock {
            mock::subscriptions(&mut next_id)
        } else {
            Vec::new()
        };
        let mut load_errors = Vec::new();
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
            });
        }
        for sub in &mut subs {
            let group = sub.name.clone();
            for server in &mut sub.servers {
                server.fp_override = fp_override_for(&config, &group, server);
            }
        }
        let mut app = Self {
            subs,
            selected: 0,
            list_state: ListState::default(),
            focus: Focus::Servers,
            screen: Screen::Main,
            mode: Mode::Proxy,
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
            core_failures: VecDeque::new(),
            config,
            storage,
            core: None,
            proxy: None,
            proxy_requested: false,
            proxy_active: false,
            mock,
            busy: false,
            run_dir: std::env::temp_dir().join("elf-gate-run"),
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
        }
    }

    /// Points the system proxy at the local core, if the user wants that and it can work.
    fn request_proxy_on(&mut self) {
        let Some(handle) = &self.proxy else { return };
        if !self.config.proxy.set_system_proxy || self.mode != Mode::Proxy || self.proxy_requested {
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
        if self.mock && matches!(self.conn, Conn::Connected(_)) {
            self.up_bytes += self.rng.next() % 2_000;
            self.down_bytes += self.rng.next() % 20_000;
        }
    }

    fn on_bg(&mut self, ev: BgEvent) {
        match ev {
            BgEvent::Log(line) => {
                self.note_core_failure(&line);
                self.push_log(line);
            }
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
                    let pid = core.pid().map(|p| p.to_string()).unwrap_or_default();
                    self.core = Some(*core);
                    self.conn = Conn::Connected(id);
                    self.request_proxy_on();
                    let name = self.server_by_id(id).map(|s| s.name.clone());
                    self.log(
                        Level::Info,
                        format!("connected to {} (xray pid {pid})", name.unwrap_or_default()),
                    );
                } else {
                    // The user cancelled while the core was starting.
                    self.spawn_stop(*core);
                }
            }
            BgEvent::CoreFailed { id, error } => {
                self.busy = false;
                self.log(Level::Error, format!("[Error] {error}"));
                if self.conn == Conn::Connecting(id) {
                    self.conn = Conn::Error("не удалось запустить ядро".into());
                    self.popup = Some(Popup::Error(error));
                    self.request_proxy_off();
                }
            }
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
            BgEvent::SubsUpdated => {
                self.status = Some("Подписки обновлены (мок)".into());
                self.log(Level::Info, "subscriptions updated (mock)");
            }
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
                        self.apply_selection(kind, selected);
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
            Popup::Input { title, mut buf } => match key.code {
                KeyCode::Esc => {}
                KeyCode::Enter => self.submit_input(buf),
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
                    self.popup = Some(Popup::Input { title, buf });
                }
            },
            Popup::Confirm { text, kind } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Char('д') | KeyCode::Enter => {
                    self.confirm(kind)
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Char('н') | KeyCode::Esc => {}
                _ => self.popup = Some(Popup::Confirm { text, kind }),
            },
            Popup::Error(_) => {}
        }
    }

    // ---------- actions ----------

    pub(crate) fn handle_action(&mut self, action: Action) {
        use Action::*;
        // Server-list actions only make sense on the main screen.
        let main_only = matches!(
            action,
            Enter | Delete | Add | Filter | PingAll | SortPing | UpdateSubs | Fingerprint
        );
        if main_only && self.screen != Screen::Main {
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
            UpdateSubs => {
                if self.mock {
                    self.status = Some("Обновление подписок...".into());
                    mock::spawn_update_subs(self.tx.clone());
                } else {
                    self.status = Some("Подписки пока не поддерживаются в этой версии".into());
                }
            }
            Add => {
                self.popup = Some(Popup::Input {
                    title: "Ссылка на сервер или подписку".into(),
                    buf: String::new(),
                })
            }
            Delete => self.ask_delete(),
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
        if self.logs_active() {
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

    fn connect(&mut self, id: u64) {
        if self.busy {
            self.status = Some("Подождите: ядро запускается или останавливается".into());
            return;
        }
        let Some(server) = self.server_by_id(id).cloned() else {
            return;
        };
        self.up_bytes = 0;
        self.down_bytes = 0;
        self.conn = Conn::Connecting(id);
        let old = self.core.take();

        if server.link.is_empty() {
            // Mock server (stage 1 demo data): no real process.
            self.log(Level::Info, format!("connecting to {} (mock)", server.name));
            if let Some(old) = old {
                self.spawn_stop(old);
            }
            // Mock rule: servers whose last ping failed refuse the connection.
            let ok = !matches!(server.ping, Ping::Timeout | Ping::Error);
            mock::spawn_connect(self.tx.clone(), id, ok);
            return;
        }

        self.log(Level::Info, format!("starting core for {}", server.name));
        self.busy = true;
        let tx = self.tx.clone();
        let core_cfg = self.config.core.clone();
        let run_dir = self.run_dir.clone();
        tokio::spawn(async move {
            if let Some(old) = old {
                old.stop().await;
            }
            // Ask Xray first, so a refused config is reported with Xray's own words
            // and the server is greyed out.
            let verdict = validate::check(&core_cfg, &server, &run_dir).await;
            let started = match verdict {
                Verdict::Rejected(reason) => {
                    let _ = tx.send(BgEvent::ServerRejected {
                        id,
                        reason: reason.clone(),
                    });
                    Err(format!("Xray отверг конфиг сервера: {reason}"))
                }
                Verdict::Accepted | Verdict::Unavailable(_) => {
                    match xray::config::build(&server, &core_cfg) {
                        Ok(cfg) => Core::start(&core_cfg, &cfg, &run_dir, tx.clone())
                            .await
                            .map_err(|e| e.to_string()),
                        Err(e) => Err(e.to_string()),
                    }
                }
            };
            let ev = match started {
                Ok(core) => BgEvent::CoreStarted {
                    id,
                    core: Box::new(core),
                },
                Err(error) => BgEvent::CoreFailed { id, error },
            };
            let _ = tx.send(ev);
        });
    }

    /// Stops a core in the background; `busy` stays set until it is done.
    fn spawn_stop(&mut self, core: Core) {
        self.busy = true;
        let tx = self.tx.clone();
        tokio::spawn(async move {
            core.stop().await;
            let _ = tx.send(BgEvent::CoreStopped);
        });
    }

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
        if self.mode == Mode::Proxy && !build_info::TUN_AVAILABLE {
            self.status = Some("Режим TUN в этой версии недоступен".into());
            return;
        }
        self.mode = match self.mode {
            Mode::Proxy => Mode::Tun,
            Mode::Tun => Mode::Proxy,
        };
        self.log(Level::Info, format!("mode: {}", mode_name(self.mode)));
        if self.mode == Mode::Tun {
            // TUN needs no system proxy (stage 5 brings the real TUN mode).
            self.request_proxy_off();
        }
        // Switching the mode while connected restarts the connection.
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
                    self.subs.remove(i);
                    if was_manual {
                        self.config.servers.clear();
                        self.save_config();
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

    fn apply_selection(&mut self, kind: SelectKind, index: usize) {
        match kind {
            SelectKind::Fingerprint(id) => {
                let fp = index
                    .checked_sub(1)
                    .and_then(|i| FINGERPRINTS.get(i))
                    .map(|f| f.to_string());
                self.set_fingerprint(id, fp);
            }
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
        self.config.overrides.retain(|o| o.server != key);
        if fp.is_some() {
            self.config.overrides.push(ServerOverride {
                server: key,
                fp: fp.clone(),
            });
        }
        self.core_failures.clear();
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

    /// Remembers core warnings/errors; a burst of them hints at a blocked handshake.
    fn note_core_failure(&mut self, line: &LogLine) {
        let from_core = line.text.starts_with("[xray");
        let noise = line.text.contains("deprecated") || line.text.contains(" started");
        if from_core && line.level != Level::Info && !noise {
            self.core_failures.push_back(Instant::now());
        }
        self.prune_failures();
    }

    fn prune_failures(&mut self) {
        while self
            .core_failures
            .front()
            .is_some_and(|t| t.elapsed() > FAILURE_WINDOW)
        {
            self.core_failures.pop_front();
        }
    }

    /// Shown in the details pane when the core runs but keeps logging failures while a
    /// fingerprint other than `firefox` is in use.
    pub fn fp_hint(&self) -> Option<&'static str> {
        let Conn::Connected(id) = self.conn else {
            return None;
        };
        let server = self.server_by_id(id)?;
        let recent = self
            .core_failures
            .iter()
            .filter(|t| t.elapsed() <= FAILURE_WINDOW)
            .count();
        let fp_matters =
            matches!(server.security, Security::Tls | Security::Reality) && !server.link.is_empty();
        (fp_matters && recent >= FAILURE_THRESHOLD && server.effective_fingerprint() != "firefox")
            .then_some("Соединения не проходят? Попробуйте fp=firefox (клавиша f)")
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

    /// Checks the given servers with `xray run -test` in the background, one after another.
    fn spawn_checks(&self, servers: Vec<Server>) {
        if servers.is_empty() {
            return;
        }
        let tx = self.tx.clone();
        let core_cfg = self.config.core.clone();
        let run_dir = self.run_dir.clone();
        tokio::spawn(async move {
            for server in servers {
                match validate::check(&core_cfg, &server, &run_dir).await {
                    Verdict::Accepted => {}
                    Verdict::Rejected(reason) => {
                        let _ = tx.send(BgEvent::ServerRejected {
                            id: server.id,
                            reason,
                        });
                    }
                    Verdict::Unavailable(why) => {
                        // Not Xray's verdict on the server (e.g. no binary yet): skip the rest.
                        let _ = tx.send(BgEvent::Log(LogLine {
                            time: now_hms(),
                            level: Level::Info,
                            text: format!("server validation skipped: {why}"),
                        }));
                        break;
                    }
                }
            }
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
            if !self.mock {
                self.popup = Some(Popup::Error(
                    "Подписки пока не поддерживаются в этой версии.\nДобавьте ссылку на отдельный сервер.".into(),
                ));
                return;
            }
            // Real subscription import arrives in stage 6; debug builds add a mock group.
            let mut servers = Vec::new();
            for n in 1..=3 {
                self.next_id += 1;
                servers.push(mock::make_server(
                    self.next_id,
                    &format!("NEW-{n}"),
                    "new.example.com",
                    Security::Reality,
                    Transport::Tcp,
                ));
            }
            self.subs.push(Subscription {
                name: format!("sub-{}", self.subs.len() + 1),
                servers,
                collapsed: false,
                info: None,
            });
            self.status = Some("Подписка добавлена (мок, без сохранения)".into());
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
        server.fp_override = fp_override_for(&self.config, MANUAL_GROUP, &server);
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
            }),
        }
        self.log(Level::Info, format!("added server {name}"));
        self.status = Some(format!("Добавлен: {name}"));
        self.save_config();
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

fn fp_override_for(config: &Config, group: &str, server: &Server) -> Option<String> {
    let key = override_key(group, server);
    config
        .overrides
        .iter()
        .find(|o| o.server == key)
        .and_then(|o| o.fp.clone())
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

    fn core_warning(text: &str) -> BgEvent {
        BgEvent::Log(LogLine {
            time: "00:00:00".into(),
            level: Level::Warning,
            text: text.into(),
        })
    }

    #[tokio::test]
    async fn burst_of_core_failures_suggests_firefox() {
        let (mut a, id) = app_with_reality();
        a.conn = Conn::Connected(id);
        assert_eq!(a.fp_hint(), None);
        for _ in 0..2 {
            a.on_bg(core_warning(
                "[xray] [Warning] proxy/vless/outbound: connection ends > EOF",
            ));
        }
        assert_eq!(a.fp_hint(), None, "two failures are not a pattern yet");
        a.on_bg(core_warning(
            "[xray:err] [Warning] reality: failed to read server hello",
        ));
        assert!(a.fp_hint().unwrap().contains("fp=firefox"));

        // Notices and non-core lines do not count; firefox already in use needs no hint.
        a.set_fingerprint(id, Some("firefox".into()));
        a.conn = Conn::Connected(id);
        for _ in 0..5 {
            a.on_bg(core_warning("[xray] [Warning] proxy: something failed"));
        }
        assert_eq!(a.fp_hint(), None);
    }

    #[tokio::test]
    async fn failure_hint_ignores_noise_and_expires() {
        let (mut a, id) = app_with_reality();
        a.conn = Conn::Connected(id);
        for _ in 0..5 {
            a.on_bg(core_warning("[xray] [Warning] core: Xray 26.11.9 started"));
            a.on_bg(core_warning(
                "[xray] [Warning] The feature gRPC is deprecated",
            ));
            a.on_bg(core_warning("some mock log line"));
        }
        assert_eq!(a.fp_hint(), None);

        let old = Instant::now() - Duration::from_secs(120);
        a.core_failures.extend([old, old, old, old]);
        assert_eq!(a.fp_hint(), None, "old failures expire");
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
        assert!(a.status.as_deref().unwrap().contains("Подписки"));

        let groups = a.subs.len();
        a.submit_input("https://example.com/sub".into());
        assert!(matches!(a.popup, Some(Popup::Error(_))));
        assert_eq!(a.subs.len(), groups, "no mock subscription may appear");
    }

    #[tokio::test]
    async fn tun_mode_is_refused_until_it_exists() {
        let mut a = app();
        a.handle_action(Action::ToggleMode);
        assert_eq!(a.mode, Mode::Proxy);
        assert!(a.status.as_deref().unwrap().contains("TUN"));
    }
}
