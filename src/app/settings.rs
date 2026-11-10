//! The settings screen: every row is one setting; Enter flips a switch, cycles a choice or
//! opens an input for a text or a number. Changes go to the background part as [`Cmd::Set`].

use super::*;
use crate::proto::Setting;
use crate::storage::PingMode;

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
    PingMode,
    PingUrl,
    PingTimeout,
    PingAuto,
    TunName,
    TunnelDns,
    AutoConnect,
    Autostart,
    Theme,
    SubUa(String),
    SubHours(String),
}

const LOG_LEVELS: [&str; 5] = ["debug", "info", "warning", "error", "none"];

fn onoff(b: bool) -> String {
    if b {
        "включено"
    } else {
        "выключено"
    }
    .into()
}

impl AppState {
    /// `(id, label, current value)` in display order.
    pub fn settings_rows(&self) -> Vec<(SettingId, String, String)> {
        let c = &self.config;
        let mut rows = vec![
            (
                SettingId::XrayPath,
                "Путь к Xray".into(),
                c.core.xray_path.clone(),
            ),
            (
                SettingId::TunXrayPath,
                "Xray для TUN (Linux)".into(),
                c.tun.xray_path.clone(),
            ),
            (
                SettingId::SocksPort,
                "Порт SOCKS".into(),
                c.core.socks_port.to_string(),
            ),
            (
                SettingId::HttpPort,
                "Порт HTTP".into(),
                c.core.http_port.to_string(),
            ),
            (
                SettingId::ApiPort,
                "Порт API (статистика)".into(),
                c.core.api_port.to_string(),
            ),
            (
                SettingId::LogLevel,
                "Уровень лога ядра".into(),
                c.core.log_level.clone(),
            ),
            (
                SettingId::VerboseLog,
                "Подробный лог ядра (access)".into(),
                onoff(c.core.verbose_log),
            ),
            (
                SettingId::SetSystemProxy,
                "Системный прокси".into(),
                onoff(c.proxy.set_system_proxy),
            ),
            (
                SettingId::PingMode,
                "Режим пинга".into(),
                match c.ping.mode {
                    PingMode::Tcp => "tcp",
                    PingMode::Url => "url",
                }
                .into(),
            ),
            (
                SettingId::PingUrl,
                "Адрес для пинга по URL".into(),
                c.ping.url.clone(),
            ),
            (
                SettingId::PingTimeout,
                "Таймаут пинга, мс".into(),
                c.ping.timeout_ms.to_string(),
            ),
            (
                SettingId::PingAuto,
                "Автопинг, с (0 = выкл)".into(),
                c.ping.auto_interval_secs.to_string(),
            ),
            (
                SettingId::TunName,
                "Имя TUN-интерфейса".into(),
                c.tun.name.clone(),
            ),
            (
                SettingId::TunnelDns,
                "DNS через туннель".into(),
                c.tun.tunnel_dns.clone(),
            ),
            (
                SettingId::AutoConnect,
                "Подключаться при запуске".into(),
                onoff(c.ui.auto_connect),
            ),
            (
                SettingId::Autostart,
                "Запускать при входе в систему".into(),
                onoff(self.autostart),
            ),
            (SettingId::Theme, "Тема".into(), c.ui.theme.clone()),
        ];
        for s in &c.subscriptions {
            rows.push((
                SettingId::SubUa(s.name.clone()),
                format!("«{}»: User-Agent", s.name),
                s.user_agent.clone(),
            ));
            rows.push((
                SettingId::SubHours(s.name.clone()),
                format!("«{}»: обновлять, ч (0 = выкл)", s.name),
                s.auto_update_hours.to_string(),
            ));
        }
        rows
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
            SettingId::AutoConnect => Setting::AutoConnect(!c.ui.auto_connect),
            SettingId::Autostart => Setting::Autostart(!self.autostart),
            SettingId::PingMode => Setting::PingMode(match c.ping.mode {
                PingMode::Tcp => PingMode::Url,
                PingMode::Url => PingMode::Tcp,
            }),
            SettingId::Theme => Setting::Theme(cycle(&["dark", "light"], &c.ui.theme)),
            SettingId::LogLevel => Setting::LogLevel(cycle(&LOG_LEVELS, &c.core.log_level)),
            other => {
                self.popup = Some(Popup::Input {
                    title: format!("{label} (сейчас: {value})"),
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
        let num = |t: &str| {
            t.parse::<u64>()
                .map_err(|_| "ожидается целое число".to_string())
        };
        let port = |t: &str| {
            t.parse::<u16>()
                .map_err(|_| "порт: число от 1024 до 65535".to_string())
        };
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
            SettingId::SubUa(name) => Ok(Setting::SubscriptionUserAgent { name, value: text }),
            SettingId::SubHours(name) => num(&text).map(|h| Setting::SubscriptionHours {
                name,
                hours: h.min(u64::from(u32::MAX)) as u32,
            }),
            _ => return,
        };
        match set {
            Ok(s) => self.send(Cmd::Set(s)),
            Err(e) => self.popup = Some(Popup::Error(e)),
        }
    }
}
