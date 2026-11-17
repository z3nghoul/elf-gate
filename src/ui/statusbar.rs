use crate::action::Action;
use crate::app::{mode_name, AppState, Conn};
use crate::ui::hits::Target;
use crate::ui::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

/// TUN and the system proxy both work at once.
fn mixed(app: &AppState) -> bool {
    app.tun_active && app.proxy_active
}

/// `PROXY`, `TUN include` / `TUN exclude`, or `TUN+PROXY include` / `TUN+PROXY exclude`.
/// After a TUN that did not start the live connection is plain `PROXY`.
fn mode_label(app: &AppState) -> String {
    if app.tun_fallback.is_some() {
        return mode_name(crate::app::Mode::Proxy).to_string();
    }
    match app.mode {
        crate::app::Mode::Proxy => mode_name(app.mode).to_string(),
        crate::app::Mode::Tun => format!(
            "{} {}",
            if mixed(app) {
                "TUN+PROXY".to_string()
            } else {
                mode_name(app.mode).to_string()
            },
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

/// A piece of the status line and what a click on it does.
type Piece = (Segment, Option<Action>);

/// A clickable stretch of a row: where it starts, how wide it is, what a click does.
type Click = (u16, u16, Action);

fn width_of(seg: &Segment) -> usize {
    seg.iter().map(|s| s.content.chars().count()).sum()
}

/// The status line as separate pieces (connection, mode, traffic, message). A piece is never cut
/// in the middle when it fits a row.
fn segments(app: &AppState, th: &Theme) -> Vec<Piece> {
    use crate::app::LinkState;
    let mut out: Vec<Piece> = Vec::new();
    let mut first: Segment = Vec::new();
    if app.privacy() {
        first.push(Span::styled(" PRIVACY ", th.privacy_badge()));
        first.push(Span::raw(" "));
    }
    match &app.link {
        LinkState::Connecting => {
            first.push(Span::styled(crate::t!("status.link_connecting"), th.warn()));
            return vec![(first, None)];
        }
        LinkState::Down(why) => {
            first.push(Span::styled(
                app.mask(&crate::t!("status.link_down", why = why)),
                th.bad(),
            ));
            return vec![(first, None)];
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
    out.push((first, None));
    let mut mode = vec![Span::styled(mode_label(app), th.title())];
    if app.tun_fallback.is_some() {
        mode.push(Span::styled(
            format!(" ({})", crate::t!("status.tun_fallback")),
            th.warn(),
        ));
    }
    if app.proxy_active && !mixed(app) {
        mode.push(Span::styled(" sys-proxy", th.good()));
    }
    // A click on the mode switches it, as the key does.
    out.push((mode, Some(Action::ToggleMode)));
    if matches!(app.conn, Conn::Connected(_)) || app.mock {
        let t = &app.traffic;
        out.push((
            vec![Span::styled(
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
            )],
            None,
        ));
    }
    if let Some(release) = &app.update {
        out.push((
            vec![Span::styled(
                crate::t!("status.update_available", version = release.version),
                th.good(),
            )],
            Some(Action::Update),
        ));
    }
    if let Some(msg) = &app.status {
        out.push((vec![Span::styled(app.mask(msg), th.warn())], None));
    }
    out
}

/// Packs the pieces into rows of at most `width` columns, separated by ` | ` inside a row.
/// A piece wider than a row is cut to it. At most [`MAX_ROWS`] rows; the rest is dropped.
pub fn rows(app: &AppState, th: &Theme, width: usize) -> Vec<Line<'static>> {
    layout(app, th, width).into_iter().map(|r| r.0).collect()
}

/// The rows and, for each, the stretches a click acts on.
fn layout(app: &AppState, th: &Theme, width: usize) -> Vec<(Line<'static>, Vec<Click>)> {
    let width = width.max(1);
    let mut rows: Vec<(Vec<Span<'static>>, Vec<Click>)> = Vec::new();
    let mut used = 0usize;
    for (mut seg, action) in segments(app, th) {
        let w = width_of(&seg);
        let sep = if rows.last().is_some_and(|r| !r.0.is_empty()) {
            3
        } else {
            0
        };
        if !rows.is_empty() && used + sep + w <= width {
            let row = rows.last_mut().expect("a row exists");
            row.0.push(Span::styled(" | ", th.muted()));
            let start = used + sep;
            row.0.extend(seg);
            if let Some(a) = action {
                row.1.push((start as u16, w as u16, a));
            }
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
        let clicks = action
            .map(|a| vec![(0, used as u16, a)])
            .unwrap_or_default();
        rows.push((seg, clicks));
    }
    rows.into_iter()
        .take(MAX_ROWS)
        .map(|(spans, clicks)| (Line::from(spans), clicks))
        .collect()
}

pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme) {
    let laid = layout(app, th, area.width as usize);
    for (y, (_, clicks)) in laid.iter().enumerate() {
        for &(x, w, action) in clicks {
            let rect = Rect::new(area.x + x, area.y + y as u16, w, 1);
            app.hits.click(rect, Target::Action(action));
        }
    }
    f.render_widget(
        Paragraph::new(laid.iter().map(|r| r.0.clone()).collect::<Vec<_>>()),
        area,
    );
    // The pointer on the mode or on the new version lights it.
    for (y, (_, clicks)) in laid.iter().enumerate() {
        for &(x, w, _) in clicks {
            let rect = Rect::new(area.x + x, area.y + y as u16, w, 1);
            if app.hits.is_hover(rect) {
                f.buffer_mut().set_style(rect, th.hover());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{format_bytes, mode_label};
    use crate::app::{AppState, Mode};

    fn app(mode: Mode) -> AppState {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut a = AppState::new(tx);
        a.mode = mode;
        a
    }

    #[test]
    fn the_mode_label_tells_tun_proxy_and_both() {
        let mut a = app(Mode::Tun);
        assert_eq!(mode_label(&a), "TUN exclude");
        a.tun_active = true;
        a.proxy_active = true;
        assert_eq!(mode_label(&a), "TUN+PROXY exclude");
        a.tun_fallback = Some("no adapter".into());
        a.tun_active = false;
        assert_eq!(
            mode_label(&a),
            "PROXY",
            "after a fall back the live mode is PROXY"
        );
        assert_eq!(mode_label(&app(Mode::Proxy)), "PROXY");
    }

    #[test]
    fn formats_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(5 * 1024 * 1024 * 1024), "5.0 GB");
    }
}
