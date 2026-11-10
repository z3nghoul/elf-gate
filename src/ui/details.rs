use crate::app::{AppState, Focus, Row, Screen};
use crate::model::server::{ping_label_with_age, Security, Server};
use crate::model::subscription::{format_date, format_datetime, unix_now};
use crate::ui::statusbar::format_bytes;
use crate::ui::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;

fn field<'a>(label: &str, value: String, th: &Theme) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{label:<13}"), th.muted()),
        Span::styled(value, th.text()),
    ])
}

/// Current fingerprint with its origin: override, link value or Xray's default.
fn fingerprint_label(s: &Server) -> String {
    let from_link = if s.tls.fingerprint.is_empty() {
        "не задан".to_string()
    } else {
        s.tls.fingerprint.clone()
    };
    match &s.fp_override {
        Some(o) if s.fp_auto => {
            format!("{o} (подобран автоматически; в ссылке: {from_link}; f - сменить)")
        }
        Some(o) => format!("{o} (выбран; в ссылке: {from_link}; f - сменить)"),
        None if s.tls.fingerprint.is_empty() && s.security == Security::Reality => {
            "chrome (по умолчанию; f - сменить)".to_string()
        }
        None => format!("{from_link} (f - сменить)"),
    }
}

/// Appends `label: value` only when the value is not empty.
fn opt<'a>(lines: &mut Vec<Line<'a>>, label: &str, value: &str, th: &Theme) {
    if !value.is_empty() {
        lines.push(field(label, value.to_string(), th));
    }
}

fn server_lines<'a>(s: &Server, th: &Theme) -> Vec<Line<'a>> {
    let mut lines = vec![field("Имя:", s.name.clone(), th)];
    if let Some(reason) = &s.unsupported {
        lines.push(Line::from(Span::styled(reason.clone(), th.warn())));
        opt(&mut lines, "Ссылка:", &s.link, th);
        return lines;
    }
    lines.push(field(
        "Протокол:",
        format!("VLESS+{}", s.security.label()),
        th,
    ));
    lines.push(field("Транспорт:", s.transport.label().into(), th));
    if let Some(note) = s.deprecated_transport() {
        lines.push(Line::from(Span::styled(note, th.warn())));
    }
    lines.push(field("Адрес:", s.host_port(), th));
    opt(&mut lines, "UUID:", &s.uuid, th);
    opt(&mut lines, "Flow:", &s.flow, th);
    if s.flow.contains("vision") {
        lines.push(field(
            "QUIC:",
            "UDP/443 закрыт самим Xray (flow=vision), пресет block-quic не нужен".into(),
            th,
        ));
    }
    if !s.encryption.eq_ignore_ascii_case("none") {
        let short: String = s.encryption.chars().take(28).collect();
        opt(&mut lines, "Encryption:", &format!("{short}..."), th);
    }
    opt(&mut lines, "SNI:", &s.tls.sni, th);
    if matches!(s.security, Security::Tls | Security::Reality) {
        lines.push(field("Fingerprint:", fingerprint_label(s), th));
    }
    if matches!(s.security, Security::Tls | Security::Reality) {
        lines.push(field(
            "Фрагмент:",
            if s.fragment {
                "включена (z - выключить)".into()
            } else {
                "выключена (z - включить)".into()
            },
            th,
        ));
    }
    opt(&mut lines, "ALPN:", &s.tls.alpn.join(","), th);
    opt(&mut lines, "PublicKey:", &s.tls.public_key, th);
    opt(&mut lines, "ShortId:", &s.tls.short_id, th);
    opt(&mut lines, "SpiderX:", &s.tls.spider_x, th);
    if s.tls.allow_insecure {
        lines.push(field("Insecure:", "да".into(), th));
    }
    opt(&mut lines, "Path:", &s.params.path, th);
    opt(&mut lines, "Host:", &s.params.host, th);
    opt(&mut lines, "Mode:", &s.params.mode, th);
    opt(&mut lines, "Service:", &s.params.service_name, th);
    lines.push(field(
        "Роль:",
        match s.role {
            Some(r) => format!("{} (b - сменить)", r.label()),
            None => "нет (b - назначить основной / запасной)".into(),
        },
        th,
    ));
    lines.push(field(
        "Пинг:",
        if s.ping_at.is_some() {
            format!(
                "{} ({})",
                ping_label_with_age(s.ping, s.ping_at, unix_now()),
                s.ping_kind.long()
            )
        } else {
            s.ping.label()
        },
        th,
    ));
    lines
}

pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme) {
    let focused = app.screen == Screen::Main && app.focus == Focus::Details;
    let lines = match app.selected_row() {
        Some(Row::Server(i, j)) => {
            let mut l = server_lines(&app.subs[i].servers[j], th);
            if app.conn == crate::app::Conn::Connected(app.subs[i].servers[j].id) {
                match &app.health {
                    crate::app::HealthState::Checking => {
                        l.push(field("Проверка:", "идёт...".into(), th));
                    }
                    crate::app::HealthState::Ok(d) => {
                        l.push(Line::from(vec![
                            Span::styled(format!("{:<13}", "Проверка:"), th.muted()),
                            Span::styled(
                                format!("трафик идёт через сервер ({} мс)", d.as_millis()),
                                th.good(),
                            ),
                        ]));
                    }
                    crate::app::HealthState::Failed(e) => {
                        l.push(Line::from(Span::styled(
                            format!("Проверка не прошла: {e}"),
                            th.bad(),
                        )));
                    }
                    crate::app::HealthState::Unknown => {}
                }
            }
            if let Some(hint) = app.fp_hint() {
                l.push(Line::from(Span::styled(hint, th.warn())));
            }
            l
        }
        Some(Row::Group(i)) => {
            let sub = &app.subs[i];
            let mut l = vec![
                field("Подписка:", sub.name.clone(), th),
                field("Серверов:", sub.servers.len().to_string(), th),
            ];
            if let Some(info) = &sub.info {
                l.push(field(
                    "Трафик:",
                    if info.total > 0 {
                        format!(
                            "{} / {}",
                            format_bytes(info.used()),
                            format_bytes(info.total)
                        )
                    } else {
                        format!("{} (лимит не указан)", format_bytes(info.used()))
                    },
                    th,
                ));
                if let Some(expire) = info.expire {
                    l.push(field("Истекает:", format_date(expire), th));
                }
            }
            if sub.is_remote {
                l.push(field(
                    "Обновлено:",
                    sub.updated.map_or("ещё не обновлялась".to_string(), |t| {
                        format!("{} UTC", format_datetime(t))
                    }),
                    th,
                ));
            }
            l
        }
        None => vec![Line::from(Span::styled(
            "Нет серверов. Нажмите a",
            th.muted(),
        ))],
    };
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::bordered()
                .title(Span::styled(" Детали ", th.title()))
                .border_style(th.border(focused)),
        ),
        area,
    );
}
