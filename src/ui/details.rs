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
        Span::styled(format!("{label:<15}"), th.muted()),
        Span::styled(value, th.text()),
    ])
}

/// Current fingerprint with its origin: override, link value or Xray's default.
fn fingerprint_label(s: &Server) -> String {
    let from_link = if s.tls.fingerprint.is_empty() {
        crate::t!("fp.unset")
    } else {
        s.tls.fingerprint.clone()
    };
    match &s.fp_override {
        Some(o) if s.fp_auto => {
            crate::t!("fp.auto", fp = o, link = from_link)
        }
        Some(o) => crate::t!("fp.chosen", fp = o, link = from_link),
        None if s.tls.fingerprint.is_empty() && s.security == Security::Reality => {
            crate::t!("fp.default")
        }
        None => crate::t!("fp.from_link", link = from_link),
    }
}

/// Appends `label: value` only when the value is not empty.
fn opt<'a>(lines: &mut Vec<Line<'a>>, label: &str, value: &str, th: &Theme) {
    if !value.is_empty() {
        lines.push(field(label, value.to_string(), th));
    }
}

fn server_lines<'a>(s: &Server, connected: bool, th: &Theme) -> Vec<Line<'a>> {
    let mut lines = vec![field(
        &crate::t!("detail.name"),
        crate::ui::text::display_name_or(&s.name, || s.host_port()),
        th,
    )];
    if let Some(reason) = &s.unsupported {
        lines.push(Line::from(Span::styled(reason.clone(), th.warn())));
        opt(&mut lines, &crate::t!("detail.link"), &s.link, th);
        return lines;
    }
    lines.push(field(
        &crate::t!("detail.protocol"),
        format!("VLESS+{}", s.security.label()),
        th,
    ));
    lines.push(field(
        &crate::t!("detail.transport"),
        s.transport.label().into(),
        th,
    ));
    if let Some(note) = s.deprecated_transport() {
        lines.push(Line::from(Span::styled(note, th.warn())));
    }
    if let Some(f) = &s.full {
        lines.push(field(
            &crate::t!("detail.chain"),
            crate::t!("detail.chain_value", count = f.hops),
            th,
        ));
    }
    lines.push(field(
        &if s.full.is_some() {
            crate::t!("detail.first_hop")
        } else {
            crate::t!("detail.address")
        },
        s.host_port(),
        th,
    ));
    opt(&mut lines, "UUID:", &s.uuid, th);
    opt(&mut lines, "Flow:", &s.flow, th);
    if s.flow.contains("vision") {
        lines.push(field("QUIC:", crate::t!("detail.quic_note"), th));
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
            &crate::t!("detail.fragment"),
            if s.fragment {
                crate::t!("detail.fragment_on")
            } else {
                crate::t!("detail.fragment_off")
            },
            th,
        ));
    }
    opt(&mut lines, "ALPN:", &s.tls.alpn.join(","), th);
    opt(&mut lines, "PublicKey:", &s.tls.public_key, th);
    opt(&mut lines, "ShortId:", &s.tls.short_id, th);
    opt(&mut lines, "SpiderX:", &s.tls.spider_x, th);
    if s.tls.allow_insecure {
        lines.push(field("Insecure:", crate::t!("detail.yes"), th));
    }
    opt(&mut lines, "Path:", &s.params.path, th);
    opt(&mut lines, "Host:", &s.params.host, th);
    opt(&mut lines, "Mode:", &s.params.mode, th);
    if s.params.extra_count() > 0 {
        lines.push(field(
            "extra:",
            crate::t!("detail.extra_count", count = s.params.extra_count()),
            th,
        ));
    }
    opt(&mut lines, "Service:", &s.params.service_name, th);
    lines.push(field(
        &crate::t!("detail.role"),
        match s.role {
            Some(r) => crate::t!("detail.role_set", role = r.label()),
            None => crate::t!("detail.role_none"),
        },
        th,
    ));
    if connected {
        lines.extend(active_ping_lines(s, th));
    } else {
        lines.push(field(
            &crate::t!("detail.ping"),
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
    }
    lines
}

/// The two latency lines of the connected server and the hint that they are different metrics.
fn active_ping_lines<'a>(s: &Server, th: &Theme) -> Vec<Line<'a>> {
    let ms = |p: crate::model::server::Ping| match p {
        crate::model::server::Ping::Ms(ms) => format!("{ms} ms"),
        other => other.label(),
    };
    let vpn = if s.vpn_samples > 0 {
        crate::t!("detail.ping_vpn", ms = ms(s.vpn), k = s.vpn_samples)
    } else {
        ms(s.vpn)
    };
    vec![
        field(&crate::t!("detail.ping_tcp"), ms(s.tcp), th),
        field(&crate::t!("detail.ping_tunnel"), vpn, th),
        Line::from(Span::styled(crate::t!("detail.ping_hint"), th.muted())),
    ]
}

pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme) {
    let focused = app.screen == Screen::Main && app.focus == Focus::Details;
    let lines = match app.selected_row() {
        Some(Row::Server(i, j)) => {
            let connected = app.conn == crate::app::Conn::Connected(app.subs[i].servers[j].id);
            let mut l = server_lines(&app.shown(&app.subs[i].servers[j]), connected, th);
            if app.conn == crate::app::Conn::Connected(app.subs[i].servers[j].id) {
                match &app.health {
                    crate::app::HealthState::Checking => {
                        l.push(field(
                            &crate::t!("detail.check"),
                            crate::t!("detail.check_running"),
                            th,
                        ));
                    }
                    crate::app::HealthState::Ok(d) => {
                        l.push(Line::from(vec![
                            Span::styled(format!("{:<15}", crate::t!("detail.check")), th.muted()),
                            Span::styled(
                                crate::t!("detail.check_ok", ms = d.as_millis()),
                                th.good(),
                            ),
                        ]));
                    }
                    crate::app::HealthState::Failed(e) => {
                        l.push(Line::from(Span::styled(
                            app.mask(&crate::t!("detail.check_failed", error = e)),
                            th.bad(),
                        )));
                    }
                    crate::app::HealthState::Unknown => {}
                }
                if app.process_unresolved > 0 {
                    l.push(field(
                        &crate::t!("detail.no_process"),
                        crate::tn!("detail.no_process_value", app.process_unresolved),
                        th,
                    ));
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
                field(&crate::t!("detail.sub"), app.group_title(&sub.name), th),
                field(
                    &crate::t!("detail.servers"),
                    sub.servers.len().to_string(),
                    th,
                ),
            ];
            if let Some(info) = &sub.info {
                l.push(field(
                    &crate::t!("detail.traffic"),
                    if info.total > 0 {
                        format!(
                            "{} / {}",
                            format_bytes(info.used()),
                            format_bytes(info.total)
                        )
                    } else {
                        crate::t!("detail.traffic_nolimit", used = format_bytes(info.used()))
                    },
                    th,
                ));
                if let Some(expire) = info.expire {
                    l.push(field(&crate::t!("detail.expires"), format_date(expire), th));
                }
            }
            if sub.is_remote {
                l.push(field(
                    &crate::t!("detail.updated"),
                    sub.updated.map_or(crate::t!("detail.never_updated"), |t| {
                        format!("{} UTC", format_datetime(t))
                    }),
                    th,
                ));
            }
            l
        }
        None => vec![Line::from(Span::styled(
            crate::t!("detail.none"),
            th.muted(),
        ))],
    };
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::bordered()
                .title(Span::styled(
                    format!(" {} ", crate::t!("detail.title")),
                    th.title(),
                ))
                .border_style(th.border(focused)),
        ),
        area,
    );
}
