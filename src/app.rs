//! The interface's state: what is selected, which screen and popup are open, the log view.
//! The data (servers, connection, rules, settings) is not owned here: it comes from the
//! background process as a [`View`], and everything the user changes is sent back as a [`Cmd`].

use crate::action::{map_key, Action};
use crate::event::{now_hms, Event, Level, LinkEvent, LogLine};
use crate::model::rule::{builtin_presets, validate, RoutingMode, Rule, RuleKind};
use crate::model::server::{Security, Server, ServerRole, Transport, FINGERPRINTS};
use crate::model::subscription::Subscription;
use crate::platform::{self, Clipboard, TunHost};
use crate::proto::{Alert, Ask, Cmd, RuleRef, Traffic, Update, View};
use crate::storage::Config;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::ListState;
pub mod settings;
pub mod subscription;
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
    /// The settings of one subscription (`AppState::sub_name`).
    Subscription,
    Help,
    LogsFull,
    /// The checks: why it does not connect.
    Diag,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmKind {
    /// Close the interface; the VPN keeps running in the background.
    Quit,
    /// Disconnect and stop the background process.
    QuitAll,
    DeleteServer(u64),
    /// Hide a subscription server (it stays hidden when the provider lists it again).
    HideServer(u64),
    /// Bring a hidden server back.
    UnhideServer(u64),
    DeleteGroup(String),
    /// A question from the background process.
    Ask(Ask),
    /// Do what a check offered.
    Fix(crate::diag::Fix),
    /// Add what the clipboard held: the texts to send as `AddLink`, one by one.
    Paste(Vec<String>),
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
    /// The User-Agent of the subscription (by name); empty means the default.
    SubUserAgent(String),
    /// The update interval of the subscription (by name); empty means the default.
    SubHours(String),
}

/// What a selection popup applies its choice to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectKind {
    Fingerprint(u64),
    /// Role of the server in the primary + backup scheme.
    Role(u64),
    /// Which kind of rule to add.
    NewRuleKind,
    /// `u`: update all, or open one subscription (index 0 is "all", then `config.subscriptions`).
    Subscriptions,
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
    /// Pick a running program for a process rule: names sorted, equal names in one row with the
    /// number of processes; typing filters the list.
    Processes {
        /// `(name, how many processes have it)`.
        items: Vec<(String, usize)>,
        filter: String,
        /// Index in the filtered list.
        selected: usize,
    },
    Error(String),
    /// A failed connection: closes like an error, `c` opens the check screen.
    ConnError(String),
    /// Information the user should read but that is not a failure.
    Notice(String),
    /// The new version: its notes and link; `s` stops the reminders about it.
    Update(crate::update::Release),
}

/// Indexes of the processes whose name contains the filter (case ignored).
pub fn process_matches(items: &[(String, usize)], filter: &str) -> Vec<usize> {
    let needle = filter.to_lowercase();
    (0..items.len())
        .filter(|&i| items[i].0.to_lowercase().contains(&needle))
        .collect()
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

/// How long a status message stays in the status line.
pub const STATUS_LIFETIME: std::time::Duration = std::time::Duration::from_secs(6);

pub struct AppState {
    // ---- mirror of the background process's view ----
    pub subs: Vec<Subscription>,
    pub mode: Mode,
    pub conn: Conn,
    pub conn_mode: Mode,
    pub tun_active: bool,
    pub proxy_active: bool,
    /// TUN did not start; the connection runs as a system proxy (the reason).
    pub tun_fallback: Option<String>,
    pub health: HealthState,
    pub config: Config,
    pub traffic: Traffic,
    /// Connections whose process the core could not find (counted, not logged).
    pub process_unresolved: u64,
    pub tray: bool,
    pub autostart: bool,
    /// A newer release is out (the status line says so, the `n` key shows the details).
    pub update: Option<crate::update::Release>,
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
    /// When the status text was set: it disappears by itself after [`STATUS_LIFETIME`].
    status_since: Option<std::time::Instant>,
    /// Ctrl+L: the main loop clears the terminal before the next frame.
    redraw_requested: bool,
    pub should_quit: bool,
    pub rules_cursor: usize,
    pub settings_cursor: usize,
    /// The subscription of [`Screen::Subscription`] and the row on it.
    pub sub_name: String,
    pub sub_cursor: usize,
    /// Where the scrolling screens and the pop-up list are (see `ui::scroll`).
    pub help_scroll: crate::ui::scroll::Scroll,
    pub settings_scroll: crate::ui::scroll::Scroll,
    pub sub_scroll: crate::ui::scroll::Scroll,
    pub rules_scroll: crate::ui::scroll::Scroll,
    pub popup_scroll: crate::ui::scroll::Scroll,
    pub link: LinkState,
    /// Servers are listed by ping instead of in their own order.
    pub sorted_by_ping: bool,
    /// The check screen: one row per check, the cursor on it, the server it looked at.
    pub diag: Vec<crate::diag::CheckResult>,
    pub diag_cursor: usize,
    pub diag_scroll: crate::ui::scroll::Scroll,
    diag_server: Option<u64>,
    /// Where a report goes when the clipboard cannot take it.
    report_dir: std::path::PathBuf,
    /// Subscriptions whose hidden servers are shown (greyed) so they can be restored.
    pub show_hidden: std::collections::HashSet<String>,
    pending_alerts: VecDeque<Alert>,
    /// After the next view the rules cursor goes to the last item (a rule was just added).
    cursor_to_end: bool,
    got_view: bool,
    tun_host: Arc<dyn TunHost>,
    clipboard: Arc<dyn Clipboard>,
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
            tun_fallback: None,
            health: HealthState::Unknown,
            config: Config::default(),
            traffic: Traffic::default(),
            process_unresolved: 0,
            tray: false,
            autostart: false,
            update: None,
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
            status_since: None,
            redraw_requested: false,
            should_quit: false,
            rules_cursor: 0,
            settings_cursor: 0,
            sub_name: String::new(),
            sub_cursor: 0,
            help_scroll: Default::default(),
            settings_scroll: Default::default(),
            sub_scroll: Default::default(),
            rules_scroll: Default::default(),
            popup_scroll: Default::default(),
            link: LinkState::Connecting,
            sorted_by_ping: false,
            diag: crate::diag::CheckId::ALL
                .iter()
                .map(|id| crate::diag::CheckResult::waiting(*id))
                .collect(),
            diag_cursor: 0,
            diag_scroll: Default::default(),
            diag_server: None,
            report_dir: crate::storage::log_dir(),
            show_hidden: std::collections::HashSet::new(),
            pending_alerts: VecDeque::new(),
            cursor_to_end: false,
            got_view: false,
            tun_host: Arc::from(platform::tun_host()),
            clipboard: Arc::from(platform::clipboard()),
            cmd_tx,
        }
    }

    #[cfg(test)]
    pub fn with_tun_host(mut self, host: Arc<dyn TunHost>) -> Self {
        self.tun_host = host;
        self
    }

    #[cfg(test)]
    pub fn with_clipboard(mut self, clipboard: Arc<dyn Clipboard>) -> Self {
        self.clipboard = clipboard;
        self
    }

    #[cfg(test)]
    pub fn with_report_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.report_dir = dir;
        self
    }

    /// Demo data for the screens, with the given config (the screen tests use it). A demo run
    /// of the program gets the same data from the background process: `build_info::demo_data`.
    pub fn with_demo(cmd_tx: UnboundedSender<Cmd>, config: Config) -> Self {
        let mut app = Self::new(cmd_tx);
        let mut next_id = 0;
        let view = View {
            groups: crate::mock::subscriptions(&mut next_id),
            conn: Conn::Disconnected,
            mode: Mode::Proxy,
            conn_mode: Mode::Proxy,
            tun_active: false,
            proxy_active: false,
            tun_fallback: None,
            health: HealthState::Unknown,
            config,
            traffic: Traffic::default(),
            process_unresolved: 0,
            tray: false,
            autostart: false,
            update: None,
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
            Update::Status(s) => self.set_status(s),
            Update::Check(result) => {
                if let Some(row) = self.diag.iter_mut().find(|r| r.id == result.id) {
                    *row = result;
                }
            }
            Update::Bye => {
                self.link = LinkState::Down(crate::t!("app.link_stopped"));
            }
        }
    }

    /// A short message in the status line (it expires, so it never outlives its news).
    pub(crate) fn set_status(&mut self, text: String) {
        self.status = Some(text);
        self.status_since = Some(std::time::Instant::now());
    }

    /// `true` once after Ctrl+L: the terminal must be cleared and drawn from scratch.
    pub fn take_redraw(&mut self) -> bool {
        std::mem::take(&mut self.redraw_requested)
    }

    /// Clears the status text once it is old enough.
    pub(crate) fn expire_status(&mut self) {
        if self
            .status_since
            .is_some_and(|t| t.elapsed() >= STATUS_LIFETIME)
        {
            self.status = None;
            self.status_since = None;
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
            tun_fallback,
            health,
            config,
            traffic,
            process_unresolved,
            tray,
            autostart,
            update,
            mock,
            ..
        } = view;
        crate::i18n::bind_thread(config.ui.language);
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
        self.tun_fallback = tun_fallback;
        self.health = health;
        self.config = config;
        self.traffic = traffic;
        self.process_unresolved = process_unresolved;
        self.tray = tray;
        self.autostart = autostart;
        self.update = update;
        self.mock = mock;
        self.got_view = true;
        // The subscription of the open screen is gone (deleted): back to the list.
        if self.screen == Screen::Subscription && self.sub_config().is_none() {
            self.screen = Screen::Main;
        }
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
            Alert::Failure(t) => Popup::ConnError(t),
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
        let shown = self.show_hidden.contains(&sub.name);
        let mut order: Vec<usize> = (0..sub.servers.len())
            .filter(|&j| shown || !sub.servers[j].hidden)
            .collect();
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
            Event::Tick => self.expire_status(),
            Event::Resize => {}
            Event::Link(l) => self.on_link(l),
        }
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) {
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
                // j / k move the choice on a Russian or Ukrainian layout too.
                let code = match key.code {
                    KeyCode::Char(c) => KeyCode::Char(crate::action::qwerty(c)),
                    other => other,
                };
                match code {
                    KeyCode::Esc => {
                        self.show_next_alert();
                        return;
                    }
                    KeyCode::Enter => {
                        self.apply_selection(kind, selected);
                        self.show_next_alert();
                        return;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        selected = (selected + 1).min(options.len() - 1)
                    }
                    KeyCode::Up | KeyCode::Char('k') => selected = selected.saturating_sub(1),
                    KeyCode::PageDown => {
                        selected = (selected + self.popup_scroll.page()).min(options.len() - 1)
                    }
                    KeyCode::PageUp => selected = selected.saturating_sub(self.popup_scroll.page()),
                    KeyCode::Home | KeyCode::Char('g') => selected = 0,
                    KeyCode::End | KeyCode::Char('G') => selected = options.len() - 1,
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
                buf,
                purpose,
            } if purpose == InputPurpose::Link && map_key(key) == Some(Action::Paste) => {
                self.popup = Some(Popup::Input {
                    title,
                    buf,
                    purpose,
                });
                self.handle_action(Action::Paste);
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
                        p @ (InputPurpose::SubUserAgent(_) | InputPurpose::SubHours(_)) => {
                            self.submit_sub_input(p, buf)
                        }
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
            Popup::Confirm { text, kind } => {
                // y / n are the physical keys, whatever the layout in use types on them (on the
                // Russian and Ukrainian ones the Y key types U+043D, the N key U+0442).
                let physical = match key.code {
                    KeyCode::Char(c) => Some(crate::action::qwerty(c).to_ascii_lowercase()),
                    _ => None,
                };
                let yes = key.code == KeyCode::Enter || matches!(physical, Some('y'));
                let no = key.code == KeyCode::Esc || matches!(physical, Some('n'));
                if yes {
                    self.confirm(kind);
                    self.show_next_alert();
                } else if no {
                    self.decline(kind);
                    self.show_next_alert();
                } else {
                    self.popup = Some(Popup::Confirm { text, kind });
                }
            }
            Popup::Processes {
                items,
                mut filter,
                mut selected,
            } => {
                let shown = process_matches(&items, &filter);
                let last = shown.len().saturating_sub(1);
                let page = self.popup_scroll.page();
                match key.code {
                    // First the filter, then the window.
                    KeyCode::Esc if !filter.is_empty() => {
                        filter.clear();
                        selected = 0;
                    }
                    KeyCode::Esc => {
                        self.show_next_alert();
                        return;
                    }
                    KeyCode::Enter => {
                        if let Some(&i) = shown.get(selected) {
                            let name = items[i].0.clone();
                            self.rules_process_chosen(0, name);
                            self.show_next_alert();
                            return;
                        }
                    }
                    KeyCode::Down => selected = (selected + 1).min(last),
                    KeyCode::Up => selected = selected.saturating_sub(1),
                    KeyCode::PageDown => selected = (selected + page).min(last),
                    KeyCode::PageUp => selected = selected.saturating_sub(page),
                    KeyCode::Home => selected = 0,
                    KeyCode::End => selected = last,
                    KeyCode::Backspace => {
                        filter.pop();
                        selected = 0;
                    }
                    KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                        filter.push(c);
                        selected = 0;
                    }
                    _ => {}
                }
                self.popup = Some(Popup::Processes {
                    items,
                    filter,
                    selected,
                });
            }
            Popup::ConnError(_) => {
                // The C key of the physical keyboard, whatever the layout.
                let check = matches!(
                    key.code,
                    KeyCode::Char(c) if crate::action::qwerty(c).eq_ignore_ascii_case(&'c')
                        && !key.modifiers.contains(KeyModifiers::CONTROL)
                );
                self.show_next_alert();
                if check && self.popup.is_none() {
                    self.handle_action(Action::Diag);
                }
            }
            Popup::Error(_) | Popup::Notice(_) => self.show_next_alert(),
            Popup::Update(release) => {
                // The notes can be longer than the window: these keys scroll them.
                let page = self.popup_scroll.page() as isize;
                let step = match key.code {
                    KeyCode::Down => Some(1),
                    KeyCode::Up => Some(-1),
                    KeyCode::PageDown => Some(page),
                    KeyCode::PageUp => Some(-page),
                    KeyCode::Home => Some(isize::MIN / 2),
                    KeyCode::End => Some(isize::MAX / 2),
                    _ => None,
                };
                if let Some(step) = step {
                    self.popup_scroll.by(step);
                    self.popup = Some(Popup::Update(release));
                    return;
                }
                // The S key of the physical keyboard, whatever the layout.
                let skip = matches!(
                    key.code,
                    KeyCode::Char(c) if crate::action::qwerty(c).eq_ignore_ascii_case(&'s')
                );
                if skip {
                    self.send(Cmd::SkipUpdate(release.version));
                }
                self.show_next_alert();
            }
        }
    }

    // ---------- actions ----------

    pub(crate) fn handle_action(&mut self, action: Action) {
        use Action::*;
        // The check screen opens from the main screen and runs again on itself.
        if action == Diag && !matches!(self.screen, Screen::Main | Screen::Diag) {
            return;
        }
        // Server-list actions only make sense on the main screen.
        let on_rules = self.screen == Screen::Rules;
        let main_only = matches!(
            action,
            Enter
                | Filter
                | PingAll
                | SortPing
                | UpdateSubs
                | Edit
                | Fold
                | Fingerprint
                | ShowHidden
                | Role
                | Fragment
        ) || (matches!(action, Delete | Add) && !on_rules);
        if main_only && self.screen != Screen::Main {
            if action == Enter && self.screen == Screen::Settings {
                self.settings_activate();
            }
            if action == Enter && self.screen == Screen::Subscription {
                self.sub_activate();
            }
            if action == Enter && self.screen == Screen::Diag {
                self.diag_fix();
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
                        text: crate::t!("confirm.quit"),
                        kind: ConfirmKind::Quit,
                    });
                } else {
                    self.should_quit = true;
                }
            }
            QuitAll => {
                self.popup = Some(Popup::Confirm {
                    text: crate::t!("confirm.quit_all"),
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
                self.set_status(if self.sorted_by_ping {
                    crate::t!("status.sort_ping")
                } else {
                    crate::t!("status.sort_original")
                });
            }
            UpdateSubs => self.open_subscriptions_menu(),
            Edit => match self.selected_row() {
                Some(Row::Group(i)) | Some(Row::Server(i, _)) => {
                    let name = self.subs[i].name.clone();
                    self.open_subscription(&name);
                }
                None => {}
            },
            Fold => {
                if let Some(Row::Group(i)) = self.selected_row() {
                    self.subs[i].collapsed = !self.subs[i].collapsed;
                }
            }
            Add => {
                if self.screen == Screen::Rules {
                    self.rules_add_menu();
                } else {
                    self.popup = Some(Popup::Input {
                        title: crate::t!("popup.add_title"),
                        buf: String::new(),
                        purpose: InputPurpose::Link,
                    })
                }
            }
            Delete if on_rules => self.rules_delete(),
            Delete => self.ask_delete(),
            Toggle => self.rules_toggle(),
            RoutingMode => self.rules_toggle_routing(),
            // On the subscription screen the key of "rules" resets the row to the default.
            Rules if self.screen == Screen::Subscription => self.sub_reset(),
            Rules => self.toggle_screen(Screen::Rules),
            Settings => self.toggle_screen(Screen::Settings),
            Logs => self.toggle_screen(Screen::LogsFull),
            Help => self.toggle_screen(Screen::Help),
            Filter => self.filtering = true,
            Fingerprint => self.open_fingerprint_menu(),
            Privacy => self.toggle_privacy(),
            Update => {
                if let Some(release) = self.update.clone() {
                    self.popup = Some(Popup::Update(release));
                }
            }
            ShowHidden => self.toggle_hidden(),
            Role => self.open_role_menu(),
            Fragment => self.toggle_fragment(),
            Back => self.back(),
            FocusNext => self.cycle_focus(true),
            FocusPrev => self.cycle_focus(false),
            Redraw => self.redraw_requested = true,
            Diag => {
                self.screen = Screen::Diag;
                self.start_checks();
            }
            CopyReport => {
                if self.screen == Screen::Diag {
                    self.copy_report();
                }
            }
            // Only the add dialog takes it: nothing to paste into elsewhere.
            Paste => {
                if matches!(
                    self.popup,
                    Some(Popup::Input {
                        purpose: InputPurpose::Link,
                        ..
                    })
                ) {
                    self.paste_from_clipboard();
                }
            }
            DebugPanic => {
                if crate::build_info::DEBUG_PANIC_KEY {
                    panic!("debug panic requested with F12");
                }
            }
        }
    }

    // ---------- privacy mode ----------

    pub fn privacy(&self) -> bool {
        self.config.ui.privacy_mode
    }

    /// Text for the screen: hidden addresses, ids, keys and URLs while privacy mode is on.
    /// Text from outside as the screen may show it: emoji and pictographs are cleaned away
    /// (they break the layout) and, in privacy mode, secrets are hidden.
    pub fn mask(&self, text: &str) -> String {
        let text = crate::ui::text::clean(text);
        if self.privacy() {
            crate::redact::text(&text, crate::redact::Mode::Full)
        } else {
            text
        }
    }

    /// The name of a server as the screen shows it; when nothing is left of it after cleaning,
    /// its address (not in privacy mode) or `server N`.
    pub fn server_title(&self, s: &Server) -> String {
        crate::ui::text::display_name_or(&s.name, || {
            if !self.privacy() && !s.address.is_empty() {
                s.host_port()
            } else {
                crate::t!("name.server", n = s.id)
            }
        })
    }

    /// The name of a subscription or group as the screen shows it.
    pub fn group_title(&self, name: &str) -> String {
        crate::ui::text::display_name_or(name, || crate::t!("name.group"))
    }

    /// A server as the screen may show it.
    pub fn shown(&self, s: &Server) -> Server {
        if self.privacy() {
            crate::redact::server(s)
        } else {
            s.clone()
        }
    }

    /// A rule's value for the screen: a rule that names a server's own address is hidden too.
    pub fn rule_value(&self, r: &Rule) -> String {
        if self.privacy()
            && matches!(r.kind, RuleKind::Ip | RuleKind::Domain)
            && self
                .subs
                .iter()
                .flat_map(|g| g.servers.iter())
                .any(|s| s.address == r.value || r.value.starts_with(&format!("{}/", s.address)))
        {
            return crate::redact::host(&r.value);
        }
        r.value.clone()
    }

    fn toggle_privacy(&mut self) {
        let next = !self.privacy();
        // At once, without waiting for the answer: a screenshot must not catch the old state.
        self.config.ui.privacy_mode = next;
        self.set_status(if next {
            crate::t!("status.privacy_on")
        } else {
            crate::t!("status.privacy_off")
        });
        self.send(Cmd::Set(crate::proto::Setting::PrivacyMode(next)));
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
        if self.screen == Screen::Settings {
            self.settings_section(forward);
            return;
        }
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
        } else if self.screen == Screen::Subscription {
            self.sub_move(delta);
        } else if self.screen == Screen::Diag {
            let last = self.diag.len().saturating_sub(1);
            self.diag_cursor = (self.diag_cursor as isize + delta).clamp(0, last as isize) as usize;
        } else if self.screen == Screen::Help {
            self.help_scroll.by(delta);
        } else if self.logs_active() {
            self.scroll_logs(delta < 0, 1);
        } else if self.servers_active() {
            self.move_selection(delta);
        }
    }

    fn page(&mut self, up: bool) {
        let n = self.log_view_h.max(1);
        let signed = |n: usize| if up { -(n as isize) } else { n as isize };
        match self.screen {
            Screen::Rules => return self.rules_move(signed(self.rules_scroll.page())),
            Screen::Settings => return self.settings_move(signed(self.settings_scroll.page())),
            Screen::Subscription => return self.sub_move(signed(self.sub_scroll.page())),
            Screen::Help => return self.help_scroll.by(signed(self.help_scroll.page())),
            _ => {}
        }
        if self.logs_active() {
            self.scroll_logs(up, n);
        } else if self.servers_active() {
            self.move_selection(if up { -(n as isize) } else { n as isize });
        }
    }

    fn jump(&mut self, top: bool) {
        let step = if top { isize::MIN / 2 } else { isize::MAX / 2 };
        match self.screen {
            Screen::Rules => return self.rules_move(step),
            Screen::Settings => return self.settings_move(step),
            Screen::Subscription => return self.sub_move(step),
            Screen::Help => {
                if top {
                    self.help_scroll.to_top()
                } else {
                    self.help_scroll.to_bottom()
                }
                return;
            }
            _ => {}
        }
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
            // A subscription header opens the subscription's screen (← → fold it).
            Some(Row::Group(i)) if self.subs[i].is_remote => {
                let name = self.subs[i].name.clone();
                self.open_subscription(&name);
            }
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
            Some(Row::Server(gi, _)) => {
                let Some(s) = self.selected_server() else {
                    return;
                };
                let remote = self.subs[gi].is_remote;
                let live =
                    matches!(self.conn, Conn::Connected(c) | Conn::Connecting(c) if c == s.id);
                let stop = if live {
                    crate::t!("confirm.live_server")
                } else {
                    String::new()
                };
                let (text, kind) = if s.hidden {
                    (
                        crate::t!("confirm.unhide", name = self.server_title(s)),
                        ConfirmKind::UnhideServer(s.id),
                    )
                } else if remote {
                    (
                        crate::t!("confirm.hide", name = self.server_title(s), stop = stop),
                        ConfirmKind::HideServer(s.id),
                    )
                } else {
                    (
                        crate::t!(
                            "confirm.delete_server",
                            name = self.server_title(s),
                            stop = stop
                        ),
                        ConfirmKind::DeleteServer(s.id),
                    )
                };
                self.popup = Some(Popup::Confirm { text, kind });
            }
            Some(Row::Group(i)) => self.ask_delete_group(i),
            None => {}
        }
    }

    pub(crate) fn ask_delete_group(&mut self, i: usize) {
        let g = &self.subs[i];
        let live = matches!(self.conn, Conn::Connected(c) | Conn::Connecting(c) if g.servers.iter().any(|s| s.id == c));
        self.popup = Some(Popup::Confirm {
            text: crate::t!(
                "confirm.delete_group",
                name = self.group_title(&g.name),
                stop = if live {
                    crate::t!("confirm.live_group")
                } else {
                    String::new()
                }
            ),
            kind: ConfirmKind::DeleteGroup(g.name.clone()),
        });
    }

    /// `h` on a subscription: show or hide the servers the user removed from it.
    fn toggle_hidden(&mut self) {
        let name = match self.selected_row() {
            Some(Row::Group(i)) | Some(Row::Server(i, _)) => self.subs[i].name.clone(),
            None => return,
        };
        let count = self
            .subs
            .iter()
            .find(|g| g.name == name)
            .map_or(0, |g| g.servers.iter().filter(|s| s.hidden).count());
        if count == 0 {
            self.set_status(crate::t!("status.no_hidden"));
            return;
        }
        if !self.show_hidden.remove(&name) {
            self.show_hidden.insert(name);
            self.set_status(crate::t!("status.hidden_shown", count = count));
        }
        self.clamp_selection();
    }

    fn confirm(&mut self, kind: ConfirmKind) {
        match kind {
            ConfirmKind::Quit => self.should_quit = true,
            ConfirmKind::QuitAll => {
                self.send(Cmd::Shutdown);
                self.should_quit = true;
            }
            ConfirmKind::Ask(ask) => self.send(Cmd::Answer { ask, yes: true }),
            ConfirmKind::Fix(fix) => {
                self.send(Cmd::ApplyFix(fix));
                self.start_checks();
            }
            ConfirmKind::Paste(texts) => {
                for text in texts {
                    self.send(Cmd::AddLink(text));
                }
            }
            ConfirmKind::DeleteServer(id) | ConfirmKind::HideServer(id) => {
                self.send(Cmd::DeleteServer(id))
            }
            ConfirmKind::UnhideServer(id) => self.send(Cmd::UnhideServer(id)),
            ConfirmKind::DeleteGroup(name) => {
                if self.screen == Screen::Subscription {
                    self.screen = Screen::Main;
                }
                self.send(Cmd::DeleteGroup(name))
            }
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
            self.set_status(crate::t!("status.pick_server"));
            return;
        };
        if server.full.is_some() {
            self.set_status(crate::t!("status.fp_full"));
            return;
        }
        if !server.is_supported() || !matches!(server.security, Security::Tls | Security::Reality) {
            self.set_status(crate::t!("status.fp_tls_only"));
            return;
        }
        let from_link = if server.tls.fingerprint.is_empty() {
            crate::t!("menu.fp_default")
        } else {
            server.tls.fingerprint.clone()
        };
        let mut options = vec![crate::t!("menu.fp_from_link", link = from_link)];
        options.extend(FINGERPRINTS.iter().map(|f| f.to_string()));
        let selected = server
            .fp_override
            .as_deref()
            .and_then(|o| FINGERPRINTS.iter().position(|f| *f == o))
            .map_or(0, |i| i + 1);
        self.popup = Some(Popup::Select {
            title: format!("TLS fingerprint: {}", self.server_title(server)),
            options,
            selected,
            kind: SelectKind::Fingerprint(server.id),
        });
    }

    /// `u`: update everything or pick one subscription.
    fn open_subscriptions_menu(&mut self) {
        if self.config.subscriptions.is_empty() {
            self.send(Cmd::UpdateSubs);
            return;
        }
        let mut options = vec![crate::t!("sub.menu_all")];
        options.extend(
            self.config
                .subscriptions
                .iter()
                .map(|s| self.group_title(&s.name)),
        );
        self.popup = Some(Popup::Select {
            title: crate::t!("sub.menu_title"),
            options,
            selected: 0,
            kind: SelectKind::Subscriptions,
        });
    }

    fn open_role_menu(&mut self) {
        let Some(server) = self.selected_server() else {
            self.set_status(crate::t!("status.pick_server"));
            return;
        };
        if !server.is_supported() || server.full.is_some() {
            self.set_status(crate::t!("status.role_link_only"));
            return;
        }
        let selected = match server.role {
            None => 0,
            Some(ServerRole::Primary) => 1,
            Some(ServerRole::Backup) => 2,
        };
        self.popup = Some(Popup::Select {
            title: crate::t!("menu.role_title", name = self.server_title(server)),
            options: vec![
                crate::t!("menu.role_none"),
                crate::t!("menu.role_primary"),
                crate::t!("menu.role_backup"),
            ],
            selected,
            kind: SelectKind::Role(server.id),
        });
    }

    fn toggle_fragment(&mut self) {
        let Some(server) = self.selected_server() else {
            self.set_status(crate::t!("status.pick_server"));
            return;
        };
        if server.full.is_some()
            || !server.is_supported()
            || !matches!(server.security, Security::Tls | Security::Reality)
        {
            self.set_status(crate::t!("status.fragment_tls_only"));
            return;
        }
        let (id, on) = (server.id, !server.fragment);
        self.send(Cmd::SetFragment { id, on });
    }

    fn apply_selection(&mut self, kind: SelectKind, index: usize) {
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
            SelectKind::Subscriptions => match index.checked_sub(1) {
                None => self.send(Cmd::UpdateSubs),
                Some(i) => {
                    if let Some(name) = self.config.subscriptions.get(i).map(|s| s.name.clone()) {
                        self.open_subscription(&name);
                    }
                }
            },
        }
    }

    /// Shown in the details pane when the connection check fails although the server answers
    /// over TCP (the check only starts after a successful TCP probe).
    pub fn fp_hint(&self) -> Option<String> {
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
        let tls_xhttp = server.security == Security::Tls && server.transport == Transport::Xhttp;
        Some(if tls_xhttp {
            crate::t!("fphint.no_traffic_tls")
        } else if fp_matters && server.effective_fingerprint() != "firefox" {
            crate::t!("fphint.retry")
        } else {
            crate::t!("fphint.no_traffic")
        })
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

    /// Ctrl+V in the add dialog: shows what the clipboard holds and asks before adding it.
    /// Without the clipboard, or with nothing usable on it, a message says so and the dialog
    /// stays open for typing by hand.
    fn paste_from_clipboard(&mut self) {
        let text = match self.clipboard.read() {
            Ok(text) => text,
            Err(e) => {
                self.set_status(crate::t!("paste.unavailable", reason = e));
                return;
            }
        };
        let found = crate::parser::paste::classify(&text);
        if found.is_empty() {
            self.set_status(crate::t!("paste.nothing"));
            return;
        }
        let known_server = |l: &String| self.config.servers.iter().any(|e| &e.link == l);
        let known_sub = |u: &String| self.config.subscriptions.iter().any(|s| &s.url == u);
        let skipped = found.servers.iter().filter(|l| known_server(l)).count()
            + found.subscriptions.iter().filter(|u| known_sub(u)).count();
        let servers: Vec<String> = found
            .servers
            .iter()
            .filter(|l| !known_server(l))
            .cloned()
            .collect();
        let subs: Vec<String> = found
            .subscriptions
            .iter()
            .filter(|u| !known_sub(u))
            .cloned()
            .collect();
        if servers.is_empty() && subs.is_empty() {
            self.popup = Some(Popup::Notice(crate::t!("paste.all_dup")));
            return;
        }
        let mut lines = Vec::new();
        if !servers.is_empty() {
            lines.push(crate::t!(
                "paste.servers",
                servers = crate::tn!("plural.servers", servers.len())
            ));
        }
        for url in &subs {
            let host = url::Url::parse(url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_string))
                .unwrap_or_default();
            lines.push(if self.privacy() {
                crate::t!("paste.subscription_hidden")
            } else {
                crate::t!("paste.subscription", host = host)
            });
        }
        if skipped > 0 {
            lines.push(crate::t!("paste.skipped", count = skipped));
        }
        self.popup = Some(Popup::Confirm {
            text: lines.join("\n"),
            kind: ConfirmKind::Paste(servers.into_iter().chain(subs).collect()),
        });
    }

    // ---------- the check screen ----------

    pub fn diag_running(&self) -> bool {
        self.diag.iter().any(|r| !r.state.finished())
            && self
                .diag
                .iter()
                .any(|r| r.state != crate::diag::State::Waiting)
    }

    /// Starts the checks over (on the main screen the selected server is the one to test).
    fn start_checks(&mut self) {
        if self.diag_running() {
            self.set_status(crate::t!("diag.busy"));
            return;
        }
        if self.screen == Screen::Diag && self.diag_server.is_none() {
            self.diag_server = self.selected_server().map(|s| s.id);
        }
        self.diag = crate::diag::CheckId::ALL
            .iter()
            .map(|id| crate::diag::CheckResult::waiting(*id))
            .collect();
        self.send(Cmd::RunChecks {
            server: self.diag_server,
        });
    }

    /// Enter on the check screen: ask before doing what the problem under the cursor offers.
    fn diag_fix(&mut self) {
        match self.diag.get(self.diag_cursor).and_then(|r| r.fix) {
            Some(fix) => {
                self.popup = Some(Popup::Confirm {
                    text: fix.question(),
                    kind: ConfirmKind::Fix(fix),
                })
            }
            None => self.set_status(crate::t!("diag.no_fix")),
        }
    }

    /// The report for the clipboard; when that is not reachable, a file in the log folder.
    fn copy_report(&mut self) {
        let input = crate::diag::ReportInput {
            version_line: crate::build_info::version_line(),
            os: platform::os_description(),
            mode: mode_name(self.mode).to_string(),
            presets: self.config.presets.enabled.clone(),
            servers: self
                .subs
                .iter()
                .flat_map(|g| g.servers.iter())
                .map(|s| crate::diag::ReportServer {
                    name: s.name.clone(),
                    address: s.address.clone(),
                })
                .collect(),
            log: self
                .logs
                .iter()
                .rev()
                .take(100)
                .rev()
                .map(|l| format!("{} {:?} {}", l.time, l.level, l.text))
                .collect(),
            results: &self.diag,
        };
        let text = crate::diag::report(&input);
        match self.clipboard.write(&text) {
            Ok(()) => self.set_status(crate::t!("diag.copied")),
            Err(reason) => {
                let path = self
                    .report_dir
                    .join(format!("check-report-{}.txt", now_hms().replace(':', "")));
                let saved = std::fs::create_dir_all(&self.report_dir)
                    .and_then(|()| std::fs::write(&path, &text));
                self.set_status(match saved {
                    Ok(()) => crate::t!(
                        "diag.saved",
                        reason = reason,
                        path = crate::redact::strip_home(&path.display().to_string())
                    ),
                    Err(e) => crate::t!("diag.not_saved", error = e),
                });
            }
        }
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
                self.set_status(crate::t!("status.preset_undeletable"));
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
            title: crate::t!("menu.rule_title"),
            options: vec![
                crate::t!("menu.rule_pick_process"),
                crate::t!("menu.rule_type_process"),
                crate::t!("menu.rule_domain"),
                crate::t!("menu.rule_ip"),
                crate::t!("menu.rule_geosite"),
                crate::t!("menu.rule_geoip"),
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
                    self.popup = Some(Popup::Notice(crate::t!("popup.no_processes")));
                } else {
                    let mut items: Vec<(String, usize)> = Vec::new();
                    for name in names {
                        match items.iter_mut().find(|i| i.0 == name) {
                            Some(i) => i.1 += 1,
                            None => items.push((name, 1)),
                        }
                    }
                    items.sort_by_cached_key(|i| (i.0.to_lowercase(), i.0.clone()));
                    self.popup = Some(Popup::Processes {
                        items,
                        filter: String::new(),
                        selected: 0,
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
            RuleKind::Process => crate::t!("hint.rule_process"),
            RuleKind::Domain => crate::t!("hint.rule_domain"),
            RuleKind::Ip => crate::t!("hint.rule_ip"),
            RuleKind::Geosite => crate::t!("hint.rule_geosite"),
            RuleKind::Geoip => crate::t!("hint.rule_geoip"),
        };
        self.popup = Some(Popup::Input {
            title: hint,
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
                    self.popup = Some(Popup::Error(crate::t!("popup.rule_exists")));
                    return;
                }
                self.cursor_to_end = true;
                self.send(Cmd::AddRule { kind, value });
            }
            Err(e) => self.popup = Some(Popup::Error(crate::t!("popup.rule_rejected", error = e))),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
