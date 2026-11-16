//! The settings screen: every row is one setting; Enter flips a switch, cycles a choice or
//! opens an input for a text or a number. Changes go to the background part as [`Cmd::Set`].

use super::*;
use crate::proto::Setting;
use crate::storage::{PingMode, UpdateChannel};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingId {
    XrayPath,
    TunXrayPath,
    SocksPort,
    HttpPort,
    ApiPort,
    LogLevel,
    VerboseLog,
    SetSystemProxy,
    ProxyWithTun,
    PingMode,
    PingUrl,
    PingTimeout,
    PingAuto,
    TunName,
    TunnelDns,
    ManageFirewall,
    AutoConnect,
    Autostart,
    CheckUpdates,
    UpdateChannel,
    Hwid,
    Theme,
    TransparentBg,
    Language,
    Privacy,
    SubDefaultUa,
    SubDefaultHours,
    SubDefaultHwid,
}

impl SettingId {
    /// Every setting (also those hidden on this platform).
    pub const ALL: [SettingId; 28] = [
        SettingId::Language,
        SettingId::Theme,
        SettingId::TransparentBg,
        SettingId::Privacy,
        SettingId::AutoConnect,
        SettingId::Autostart,
        SettingId::SetSystemProxy,
        SettingId::ManageFirewall,
        SettingId::TunXrayPath,
        SettingId::TunName,
        SettingId::TunnelDns,
        SettingId::ProxyWithTun,
        SettingId::SubDefaultUa,
        SettingId::SubDefaultHours,
        SettingId::SubDefaultHwid,
        SettingId::PingMode,
        SettingId::PingUrl,
        SettingId::PingTimeout,
        SettingId::PingAuto,
        SettingId::XrayPath,
        SettingId::LogLevel,
        SettingId::VerboseLog,
        SettingId::CheckUpdates,
        SettingId::UpdateChannel,
        SettingId::SocksPort,
        SettingId::HttpPort,
        SettingId::ApiPort,
        SettingId::Hwid,
    ];

    /// What the setting does, in plain words, for the line under the table.
    pub fn explain(&self) -> String {
        crate::t!(match self {
            SettingId::Language => "explain.language",
            SettingId::Theme => "explain.theme",
            SettingId::TransparentBg => "explain.transparent_bg",
            SettingId::Privacy => "explain.privacy",
            SettingId::AutoConnect => "explain.auto_connect",
            SettingId::Autostart => "explain.autostart",
            SettingId::SetSystemProxy => "explain.system_proxy",
            SettingId::ManageFirewall => "explain.firewall",
            SettingId::TunXrayPath => "explain.tun_xray_path",
            SettingId::TunName => "explain.tun_name",
            SettingId::TunnelDns => "explain.tunnel_dns",
            SettingId::ProxyWithTun => "explain.proxy_with_tun",
            SettingId::SubDefaultUa => "explain.sub_default_ua",
            SettingId::SubDefaultHours => "explain.sub_default_hours",
            SettingId::SubDefaultHwid => "explain.sub_default_hwid",
            SettingId::PingMode => "explain.ping_mode",
            SettingId::PingUrl => "explain.ping_url",
            SettingId::PingTimeout => "explain.ping_timeout",
            SettingId::PingAuto => "explain.ping_auto",
            SettingId::XrayPath => "explain.xray_path",
            SettingId::LogLevel => "explain.log_level",
            SettingId::VerboseLog => "explain.verbose_log",
            SettingId::CheckUpdates => "explain.check_updates",
            SettingId::UpdateChannel => "explain.update_channel",
            SettingId::SocksPort => "explain.socks_port",
            SettingId::HttpPort => "explain.http_port",
            SettingId::ApiPort => "explain.api_port",
            SettingId::Hwid => "explain.hwid",
        })
    }
}

/// The groups of the settings screen, in the order they are shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Appearance,
    Connection,
    Subscriptions,
    Tun,
    Ping,
    Core,
    Updates,
    Ports,
    Device,
}

impl Section {
    pub fn title(self) -> String {
        crate::t!(match self {
            Section::Appearance => "section.appearance",
            Section::Connection => "section.connection",
            Section::Subscriptions => "section.subscriptions",
            Section::Tun => "section.tun",
            Section::Ping => "section.ping",
            Section::Core => "section.core",
            Section::Updates => "section.updates",
            Section::Ports => "section.ports",
            Section::Device => "section.device",
        })
    }
}

pub fn section_of(id: &SettingId) -> Section {
    use SettingId::*;
    match id {
        Language | Theme | TransparentBg | Privacy => Section::Appearance,
        AutoConnect | Autostart | SetSystemProxy | ManageFirewall => Section::Connection,
        SubDefaultUa | SubDefaultHours | SubDefaultHwid => Section::Subscriptions,
        TunXrayPath | TunName | TunnelDns | ProxyWithTun => Section::Tun,
        PingMode | PingUrl | PingTimeout | PingAuto => Section::Ping,
        XrayPath | LogLevel | VerboseLog => Section::Core,
        CheckUpdates | UpdateChannel => Section::Updates,
        SocksPort | HttpPort | ApiPort => Section::Ports,
        Hwid => Section::Device,
    }
}

/// What the platform has: a setting that does nothing here is not shown (a dimmed row with
/// an explanation would only take room on a 24-line screen).
fn available(id: &SettingId, windows: bool) -> bool {
    match id {
        SettingId::ManageFirewall => windows,
        SettingId::TunXrayPath => !windows,
        _ => true,
    }
}

const LOG_LEVELS: [&str; 5] = ["debug", "info", "warning", "error", "none"];

fn onoff(b: bool) -> String {
    if b {
        crate::t!("setting.on")
    } else {
        crate::t!("setting.off")
    }
}

impl AppState {
    /// `(id, label, current value)` in display order, for this platform.
    pub fn settings_rows(&self) -> Vec<(SettingId, String, String)> {
        self.settings_rows_for(crate::platform::IS_WINDOWS)
    }

    /// The rows grouped by section (a stable sort keeps the order inside a section).
    pub fn settings_rows_for(&self, windows: bool) -> Vec<(SettingId, String, String)> {
        let mut rows = self.settings_rows_unsorted();
        rows.retain(|r| available(&r.0, windows));
        // By section, then in the order of `SettingId::ALL`.
        let rank = |id: &SettingId| {
            SettingId::ALL
                .iter()
                .position(|x| x == id)
                .unwrap_or(usize::MAX)
        };
        rows.sort_by_key(|r| (section_of(&r.0) as u8, rank(&r.0)));
        rows
    }

    fn settings_rows_unsorted(&self) -> Vec<(SettingId, String, String)> {
        let c = &self.config;
        let mut rows = vec![
            (
                SettingId::Language,
                crate::t!("setting.language"),
                crate::i18n::current().native_name().to_string(),
            ),
            (
                SettingId::XrayPath,
                crate::t!("setting.xray_path"),
                c.core.xray_path.clone(),
            ),
            (
                SettingId::TunXrayPath,
                crate::t!("setting.tun_xray_path"),
                c.tun.xray_path.clone(),
            ),
            (
                SettingId::SocksPort,
                crate::t!("setting.socks_port"),
                c.core.socks_port.to_string(),
            ),
            (
                SettingId::HttpPort,
                crate::t!("setting.http_port"),
                c.core.http_port.to_string(),
            ),
            (
                SettingId::ApiPort,
                crate::t!("setting.api_port"),
                c.core.api_port.to_string(),
            ),
            (
                SettingId::LogLevel,
                crate::t!("setting.log_level"),
                c.core.log_level.clone(),
            ),
            (
                SettingId::VerboseLog,
                crate::t!("setting.verbose_log"),
                onoff(c.core.verbose_log),
            ),
            (
                SettingId::SetSystemProxy,
                crate::t!("setting.system_proxy"),
                onoff(c.proxy.set_system_proxy),
            ),
            (
                SettingId::ProxyWithTun,
                crate::t!("setting.proxy_with_tun"),
                onoff(c.proxy.with_tun),
            ),
            (
                SettingId::PingMode,
                crate::t!("setting.ping_mode"),
                match c.ping.mode {
                    PingMode::Tcp => "tcp",
                    PingMode::Url => "url",
                }
                .into(),
            ),
            (
                SettingId::PingUrl,
                crate::t!("setting.ping_url"),
                c.ping.url.clone(),
            ),
            (
                SettingId::PingTimeout,
                crate::t!("setting.ping_timeout"),
                c.ping.timeout_ms.to_string(),
            ),
            (
                SettingId::PingAuto,
                crate::t!("setting.ping_auto"),
                c.ping.auto_interval_secs.to_string(),
            ),
            (
                SettingId::TunName,
                crate::t!("setting.tun_name"),
                c.tun.name.clone(),
            ),
            (
                SettingId::TunnelDns,
                crate::t!("setting.tunnel_dns"),
                c.tun.tunnel_dns.clone(),
            ),
            (
                SettingId::ManageFirewall,
                crate::t!("setting.firewall"),
                onoff(c.tun.manage_firewall),
            ),
            (
                SettingId::AutoConnect,
                crate::t!("setting.auto_connect"),
                onoff(c.ui.auto_connect),
            ),
            (
                SettingId::Autostart,
                crate::t!("setting.autostart"),
                onoff(self.autostart),
            ),
            (
                SettingId::CheckUpdates,
                crate::t!("setting.check_updates"),
                onoff(c.updates.check),
            ),
            (
                SettingId::UpdateChannel,
                crate::t!("setting.update_channel"),
                match c.updates.channel {
                    UpdateChannel::Stable => crate::t!("setting.channel_stable"),
                    UpdateChannel::Test => crate::t!("setting.channel_test"),
                },
            ),
            (
                SettingId::Hwid,
                crate::t!("setting.hwid"),
                c.device.hwid.clone(),
            ),
            (
                SettingId::Privacy,
                crate::t!("setting.privacy"),
                onoff(c.ui.privacy_mode),
            ),
            (
                SettingId::Theme,
                crate::t!("setting.theme"),
                crate::ui::theme::canonical(&c.ui.theme).to_string(),
            ),
        ];
        // Only the themes that have a background of their own can make it transparent.
        if crate::ui::theme::canonical(&c.ui.theme) != "terminal" {
            rows.push((
                SettingId::TransparentBg,
                crate::t!("setting.transparent_bg"),
                onoff(c.ui.transparent_bg),
            ));
        }
        let d = &c.sub_defaults;
        rows.push((
            SettingId::SubDefaultUa,
            crate::t!("setting.sub_default_ua"),
            d.user_agent.clone(),
        ));
        rows.push((
            SettingId::SubDefaultHours,
            crate::t!("setting.sub_default_hours"),
            d.auto_update_hours.to_string(),
        ));
        rows.push((
            SettingId::SubDefaultHwid,
            crate::t!("setting.sub_default_hwid"),
            onoff(d.send_hwid),
        ));
        rows
    }

    /// Jump to the first row of the next or the previous section.
    pub(super) fn settings_section(&mut self, forward: bool) {
        let rows = self.settings_rows();
        let cur = self.settings_cursor.min(rows.len().saturating_sub(1));
        let sec = |i: usize| section_of(&rows[i].0);
        let first_of = |sect: Section| rows.iter().position(|r| section_of(&r.0) == sect);
        let Some(here) = rows.get(cur).map(|r| section_of(&r.0)) else {
            return;
        };
        let target = if forward {
            (cur + 1..rows.len()).map(sec).find(|s| *s != here)
        } else if first_of(here) != Some(cur) {
            Some(here)
        } else {
            (0..cur).rev().map(sec).find(|s| *s != here)
        };
        if let Some(i) = target.and_then(first_of) {
            self.settings_cursor = i;
        }
    }

    pub(super) fn settings_move(&mut self, delta: isize) {
        let len = self.settings_rows().len() as isize;
        self.settings_cursor = (self.settings_cursor as isize + delta).clamp(0, len - 1) as usize;
    }

    pub(super) fn settings_activate(&mut self) {
        let rows = self.settings_rows();
        let Some((id, label, value)) = rows.get(self.settings_cursor).cloned() else {
            return;
        };
        let c = self.config.clone();
        let cycle = |options: &[&str], current: &str| -> String {
            let i = options
                .iter()
                .position(|o| *o == current)
                .map_or(0, |i| i + 1);
            options[i % options.len()].to_string()
        };
        let set = match id {
            SettingId::VerboseLog => Setting::VerboseLog(!c.core.verbose_log),
            SettingId::SetSystemProxy => Setting::SetSystemProxy(!c.proxy.set_system_proxy),
            SettingId::ProxyWithTun => Setting::ProxyWithTun(!c.proxy.with_tun),
            SettingId::ManageFirewall => Setting::ManageFirewall(!c.tun.manage_firewall),
            SettingId::AutoConnect => Setting::AutoConnect(!c.ui.auto_connect),
            SettingId::Autostart => Setting::Autostart(!self.autostart),
            SettingId::CheckUpdates => Setting::CheckUpdates(!c.updates.check),
            SettingId::UpdateChannel => Setting::UpdateChannel(match c.updates.channel {
                UpdateChannel::Stable => UpdateChannel::Test,
                UpdateChannel::Test => UpdateChannel::Stable,
            }),
            SettingId::PingMode => Setting::PingMode(match c.ping.mode {
                PingMode::Tcp => PingMode::Url,
                PingMode::Url => PingMode::Tcp,
            }),
            SettingId::Privacy => Setting::PrivacyMode(!c.ui.privacy_mode),
            SettingId::SubDefaultHwid => Setting::SubDefaultHwid(!c.sub_defaults.send_hwid),
            SettingId::Hwid => {
                self.popup = Some(Popup::Notice(crate::t!(
                    "setting.hwid_info",
                    hwid = if c.ui.privacy_mode {
                        crate::redact::hwid(&c.device.hwid)
                    } else {
                        c.device.hwid.clone()
                    }
                )));
                return;
            }
            SettingId::Language => Setting::Language(c.ui.language.next()),
            SettingId::Theme => Setting::Theme(cycle(
                &crate::ui::theme::THEMES,
                crate::ui::theme::canonical(&c.ui.theme),
            )),
            SettingId::TransparentBg => Setting::TransparentBg(!c.ui.transparent_bg),
            SettingId::LogLevel => Setting::LogLevel(cycle(&LOG_LEVELS, &c.core.log_level)),
            other => {
                self.popup = Some(Popup::Input {
                    title: crate::t!("setting.input_title", label = label, value = value),
                    buf: value,
                    purpose: InputPurpose::Setting(other),
                });
                return;
            }
        };
        self.send(Cmd::Set(set));
    }

    /// The typed text of a text or number row; a bad number is explained here.
    pub(super) fn submit_setting(&mut self, id: SettingId, text: String) {
        let text = text.trim().to_string();
        let num = |t: &str| t.parse::<u64>().map_err(|_| crate::t!("setting.err_int"));
        let port = |t: &str| t.parse::<u16>().map_err(|_| crate::t!("setting.err_port"));
        let set: Result<Setting, String> = match id {
            SettingId::XrayPath => Ok(Setting::XrayPath(text)),
            SettingId::TunXrayPath => Ok(Setting::TunXrayPath(text)),
            SettingId::SocksPort => port(&text).map(Setting::SocksPort),
            SettingId::HttpPort => port(&text).map(Setting::HttpPort),
            SettingId::ApiPort => port(&text).map(Setting::ApiPort),
            SettingId::PingUrl => Ok(Setting::PingUrl(text)),
            SettingId::PingTimeout => num(&text).map(Setting::PingTimeoutMs),
            SettingId::PingAuto => num(&text).map(Setting::PingAutoIntervalSecs),
            SettingId::TunName => Ok(Setting::TunName(text)),
            SettingId::TunnelDns => Ok(Setting::TunnelDns(text)),
            SettingId::SubDefaultUa => Ok(Setting::SubDefaultUserAgent(text)),
            SettingId::SubDefaultHours => {
                num(&text).map(|h| Setting::SubDefaultHours(h.min(u64::from(u32::MAX)) as u32))
            }
            _ => return,
        };
        match set {
            Ok(s) => self.send(Cmd::Set(s)),
            Err(e) => self.popup = Some(Popup::Error(e)),
        }
    }
}
