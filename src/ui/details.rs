use crate::app::{AppState, Focus, Row, Screen};
use crate::model::server::Server;
use crate::ui::statusbar::format_bytes;
use crate::ui::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

fn field<'a>(label: &str, value: String, th: &Theme) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{label:<13}"), th.muted()),
        Span::styled(value, th.text()),
    ])
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
    lines.push(field("Адрес:", s.host_port(), th));
    opt(&mut lines, "UUID:", &s.uuid, th);
    opt(&mut lines, "Flow:", &s.flow, th);
    if !s.encryption.eq_ignore_ascii_case("none") {
        let short: String = s.encryption.chars().take(28).collect();
        opt(&mut lines, "Encryption:", &format!("{short}..."), th);
    }
    opt(&mut lines, "SNI:", &s.tls.sni, th);
    opt(&mut lines, "Fingerprint:", &s.tls.fingerprint, th);
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
    lines.push(field("Пинг:", s.ping.label(), th));
    lines
}

pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme) {
    let focused = app.screen == Screen::Main && app.focus == Focus::Details;
    let lines = match app.selected_row() {
        Some(Row::Server(i, j)) => server_lines(&app.subs[i].servers[j], th),
        Some(Row::Group(i)) => {
            let sub = &app.subs[i];
            let mut l = vec![
                field("Подписка:", sub.name.clone(), th),
                field("Серверов:", sub.servers.len().to_string(), th),
            ];
            if let Some(info) = &sub.info {
                l.push(field(
                    "Трафик:",
                    format!("{} / {}", format_bytes(info.used), format_bytes(info.total)),
                    th,
                ));
                l.push(field("Истекает:", info.expire.clone(), th));
            }
            l
        }
        None => vec![Line::from(Span::styled(
            "Нет серверов. Нажмите a",
            th.muted(),
        ))],
    };
    f.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .title(Span::styled(" Детали ", th.title()))
                .border_style(th.border(focused)),
        ),
        area,
    );
}
