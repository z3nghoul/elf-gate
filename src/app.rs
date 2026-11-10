use crate::action::{map_key, Action};
use crate::event::{now_hms, BgEvent, BgTx, Event, Level, LogLine};
use crate::mock::{self, Lcg};
use crate::model::server::{Ping, Security, Server, Transport};
use crate::model::subscription::Subscription;
use crate::parser;
use crate::storage::{Config, ServerEntry, Storage};
use crate::xray::{self, process::Core};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::ListState;
use std::collections::VecDeque;
use std::path::PathBuf;

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

#[derive(Debug, Clone)]
pub enum Popup {
    Input { title: String, buf: String },
    Confirm { text: String, kind: ConfirmKind },
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
    pub config: Config,
    storage: Option<Storage>,
    /// The running Xray process, if any.
    core: Option<Core>,
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
        Self::with_config(tx, Config::default(), None)
    }

    pub fn with_config(tx: BgTx, config: Config, storage: Option<Storage>) -> Self {
        let mut next_id = 0;
        // Subscriptions are still mock data until stage 6.
        let mut subs = mock::subscriptions(&mut next_id);
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
            config,
            storage,
            core: None,
            busy: false,
            run_dir: std::env::temp_dir().join("elf-gate-run"),
            next_id,
            tx,
            rng: Lcg::from_clock(),
        };
        app.log(
            Level::Info,
            "elf-gate started (subscriptions are mock data)",
        );
        for e in load_errors {
            app.log(Level::Warning, format!("skipped saved server, {e}"));
        }
        app
    }

    /// Directory for generated core configs (`run/`).
    pub fn with_run_dir(mut self, dir: PathBuf) -> Self {
        self.run_dir = dir;
        self
    }

    /// Stops the core before the application exits.
    pub async fn shutdown(&mut self) {
        if let Some(core) = self.core.take() {
            core.stop().await;
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
            Event::Resize => {}
            Event::Tick => self.on_tick(),
            Event::Bg(bg) => self.on_bg(bg),
        }
    }

    fn on_tick(&mut self) {
        self.poll_core();
        if matches!(self.conn, Conn::Connected(_)) {
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
                    let pid = core.pid().map(|p| p.to_string()).unwrap_or_default();
                    self.core = Some(*core);
                    self.conn = Conn::Connected(id);
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
                }
            }
            BgEvent::CoreStopped => self.busy = false,
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

    fn handle_action(&mut self, action: Action) {
        use Action::*;
        // Server-list actions only make sense on the main screen.
        let main_only = matches!(
            action,
            Enter | Delete | Add | Filter | PingAll | SortPing | UpdateSubs
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
                self.status = Some("Обновление подписок...".into());
                mock::spawn_update_subs(self.tx.clone());
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
            let started = match xray::config::build(&server, &core_cfg) {
                Ok(cfg) => Core::start(&core_cfg, &cfg, &run_dir, tx.clone())
                    .await
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
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
    }

    /// Detects a core that died on its own.
    fn poll_core(&mut self) {
        let Some(core) = &mut self.core else { return };
        let Some(info) = core.try_exit() else { return };
        self.core = None;
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
        self.mode = match self.mode {
            Mode::Proxy => Mode::Tun,
            Mode::Tun => Mode::Proxy,
        };
        self.log(Level::Info, format!("mode: {}", mode_name(self.mode)));
        // Switching the mode while connected restarts the connection.
        if let Conn::Connected(id) | Conn::Connecting(id) = self.conn {
            self.connect(id);
        }
    }

    fn ping_all(&mut self) {
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

    fn submit_input(&mut self, text: String) {
        let text = text.trim().to_string();
        if text.starts_with("http://") || text.starts_with("https://") {
            // Real subscription import arrives in stage 6; for now add a mock group.
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
        self.config.servers.push(ServerEntry {
            link: server.link.clone(),
        });
        let name = server.name.clone();
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
}
