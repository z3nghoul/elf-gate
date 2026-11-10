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

/// The longest the status line may grow: the panels give these rows up, no more.
pub const MAX_ROWS: usize = 3;

type Segment = Vec<Span<'static>>;

fn width_of(seg: &Segment) -> usize {
    seg.iter().map(|s| s.content.chars().count()).sum()
}

/// The status line as separate pieces (connection, mode, traffic, message). A piece is never cut
/// in the middle when it fits a row.
fn segments(app: &AppState, th: &Theme) -> Vec<Segment> {
    use crate::app::LinkState;
    let mut out: Vec<Segment> = Vec::new();
    let mut first: Segment = Vec::new();
    if app.privacy() {
        first.push(Span::styled(" PRIVACY ", th.privacy_badge()));
        first.push(Span::raw(" "));
    }
    match &app.link {
        LinkState::Connecting => {
            first.push(Span::styled(crate::t!("status.link_connecting"), th.warn()));
            return vec![first];
        }
        LinkState::Down(why) => {
            first.push(Span::styled(
                app.mask(&crate::t!("status.link_down", why = why)),
                th.bad(),
            ));
            return vec![first];
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
                    .map(|s| app.server_title(s))
                    .unwrap_or_else(|| "?".into())
            ),
        ),
        Conn::Connected(id) => (
            th.good(),
            crate::t!(
                "status.connected",
                name = app
                    .server_by_id(*id)
                    .map(|s| app.server_title(s))
                    .unwrap_or_else(|| "?".into())
            ),
        ),
        Conn::Error(e) => (th.bad(), app.mask(&crate::t!("status.error", error = e))),
    };
    first.push(Span::styled("\u{25cf} ", dot_style));
    first.push(Span::styled(text, th.text()));
    out.push(first);
    let mut mode = vec![Span::styled(mode_label(app), th.title())];
    if app.proxy_active {
        mode.push(Span::styled(" sys-proxy", th.good()));
    }
    out.push(mode);
    if matches!(app.conn, Conn::Connected(_)) || app.mock {
        let t = &app.traffic;
        out.push(vec![Span::styled(
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
        )]);
    }
    if let Some(msg) = &app.status {
        out.push(vec![Span::styled(app.mask(msg), th.warn())]);
    }
    out
}

/// Packs the pieces into rows of at most `width` columns, separated by ` | ` inside a row.
/// A piece wider than a row is cut to it. At most [`MAX_ROWS`] rows; the rest is dropped.
pub fn rows(app: &AppState, th: &Theme, width: usize) -> Vec<Line<'static>> {
    let width = width.max(1);
    let mut rows: Vec<Vec<Span<'static>>> = Vec::new();
    let mut used = 0usize;
    for mut seg in segments(app, th) {
        let w = width_of(&seg);
        let sep = if rows.last().is_some_and(|r| !r.is_empty()) {
            3
        } else {
            0
        };
        if !rows.is_empty() && used + sep + w <= width {
            let row = rows.last_mut().expect("a row exists");
            row.push(Span::styled(" | ", th.muted()));
            row.extend(seg);
            used += sep + w;
            continue;
        }
        if w > width {
            // Cut the piece to a row, keeping the style of the part that stays.
            let mut left = width;
            seg = seg
                .into_iter()
                .filter_map(|s| {
                    if left == 0 {
                        return None;
                    }
                    let take: String = s.content.chars().take(left).collect();
                    left -= take.chars().count();
                    Some(Span::styled(take, s.style))
                })
                .collect();
        }
        used = width_of(&seg);
        rows.push(seg);
    }
    rows.into_iter().take(MAX_ROWS).map(Line::from).collect()
}

pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme) {
    let lines = rows(app, th, area.width as usize);
    f.render_widget(Paragraph::new(lines), area);
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
