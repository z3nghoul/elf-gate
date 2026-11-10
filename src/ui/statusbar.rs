use crate::app::{mode_name, AppState, Conn};
use crate::ui::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

/// `PROXY`, or `TUN include` / `TUN exclude`.
fn mode_label(app: &AppState) -> String {
    match app.mode {
        crate::app::Mode::Proxy => mode_name(app.mode).to_string(),
        crate::app::Mode::Tun => format!(
            "{} {}",
            mode_name(app.mode),
            match app.config.mode.routing {
                crate::model::rule::RoutingMode::Exclude => "exclude",
                crate::model::rule::RoutingMode::Include => "include",
            }
        ),
    }
}

pub fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme) {
    use crate::app::LinkState;
    let privacy_badge = |mut spans: Vec<Span<'static>>| -> Line<'static> {
        if app.privacy() {
            spans.insert(0, Span::styled(" PRIVACY ", th.privacy_badge()));
            spans.insert(1, Span::raw(" "));
        }
        Line::from(spans)
    };
    match &app.link {
        LinkState::Connecting => {
            f.render_widget(
                Paragraph::new(privacy_badge(vec![Span::styled(
                    crate::t!("status.link_connecting"),
                    th.warn(),
                )])),
                area,
            );
            return;
        }
        LinkState::Down(why) => {
            f.render_widget(
                Paragraph::new(privacy_badge(vec![Span::styled(
                    app.mask(&crate::t!("status.link_down", why = why)),
                    th.bad(),
                )])),
                area,
            );
            return;
        }
        LinkState::Up => {}
    }
    let (dot_style, text) = match &app.conn {
        Conn::Disconnected => (th.muted(), crate::t!("status.disconnected")),
        Conn::Connecting(id) => (
            th.warn(),
            crate::t!(
                "status.connecting",
                name = app
                    .server_by_id(*id)
                    .map(|s| s.name.as_str())
                    .unwrap_or("?")
            ),
        ),
        Conn::Connected(id) => (
            th.good(),
            crate::t!(
                "status.connected",
                name = app
                    .server_by_id(*id)
                    .map(|s| s.name.as_str())
                    .unwrap_or("?")
            ),
        ),
        Conn::Error(e) => (th.bad(), app.mask(&crate::t!("status.error", error = e))),
    };
    let sep = Span::styled(" | ", th.muted());
    let mut spans = vec![
        Span::styled("● ", dot_style),
        Span::styled(text, th.text()),
        sep.clone(),
        Span::styled(mode_label(app), th.title()),
    ];
    if app.proxy_active {
        spans.push(Span::styled(" sys-proxy", th.good()));
    }
    if matches!(app.conn, Conn::Connected(_)) || app.mock {
        let t = &app.traffic;
        spans.extend([
            sep.clone(),
            Span::styled(
                crate::t!(
                    "status.traffic",
                    up = format_bytes(t.speed_up),
                    down = format_bytes(t.speed_down),
                    pu = format_bytes(t.proxy_up),
                    pd = format_bytes(t.proxy_down),
                    du = format_bytes(t.direct_up),
                    dd = format_bytes(t.direct_down),
                ),
                th.text(),
            ),
        ]);
    }
    if let Some(msg) = &app.status {
        spans.push(sep.clone());
        spans.push(Span::styled(app.mask(msg), th.warn()));
    }
    f.render_widget(Paragraph::new(privacy_badge(spans)), area);
}

#[cfg(test)]
mod tests {
    use super::format_bytes;

    #[test]
    fn formats_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(5 * 1024 * 1024 * 1024), "5.0 GB");
    }
}
