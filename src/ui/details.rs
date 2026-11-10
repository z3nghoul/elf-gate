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
        Span::styled(format!("{label:<11}"), th.muted()),
        Span::styled(value, th.text()),
    ])
}

fn server_lines<'a>(s: &Server, th: &Theme) -> Vec<Line<'a>> {
    let mut lines = vec![
        field("Имя:", s.name.clone(), th),
        field("Протокол:", format!("VLESS+{}", s.security.label()), th),
        field("Транспорт:", s.transport.label().into(), th),
        field("Адрес:", format!("{}:{}", s.address, s.port), th),
    ];
    if !s.sni.is_empty() {
        lines.push(field("SNI:", s.sni.clone(), th));
    }
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
