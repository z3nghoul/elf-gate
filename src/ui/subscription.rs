//! The screen of one subscription.

use crate::action::Action;
use crate::app::subscription::{Origin, SubRow};
use crate::app::AppState;
use crate::ui::hits::{Rows, Target, Wheel};
use crate::ui::scroll::{self, Content};
use crate::ui::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::Frame;

pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme) {
    let [area, foot] = ratatui::layout::Layout::vertical([
        ratatui::layout::Constraint::Min(3),
        ratatui::layout::Constraint::Length(crate::ui::explain::HEIGHT),
    ])
    .areas(area);
    let fields = app.sub_fields();
    let label_w = fields
        .iter()
        .map(|x| unicode_width::UnicodeWidthStr::width(x.label.as_str()))
        .max()
        .unwrap_or(0)
        + 2;
    // The action rows (update, delete) work at one click: they select and press Enter.
    let clicks: Vec<scroll::Spot> = fields
        .iter()
        .enumerate()
        .map(|(n, x)| {
            scroll::row(
                n,
                if matches!(x.row, SubRow::Update | SubRow::Delete) {
                    Target::RowAction(Rows::Sub, n, Action::Enter)
                } else {
                    Target::Row(Rows::Sub, n)
                },
            )
        })
        .collect();
    let lines: Vec<Line> = fields
        .iter()
        .map(|x| {
            let value = match x.row {
                // A subscription URL is a secret: in privacy mode only its scheme is left.
                SubRow::Url if app.privacy() => crate::redact::url(&x.value),
                _ => app.mask(&x.value),
            };
            let tag = match x.origin {
                Origin::Fixed => String::new(),
                Origin::Default => format!(" {}", crate::t!("sub.default")),
                Origin::Own => format!(" {}", crate::t!("sub.own")),
            };
            let action = matches!(x.row, SubRow::Update | SubRow::Delete);
            let label_style = match x.row {
                SubRow::Delete => th.bad(),
                SubRow::Update => th.info(),
                _ => th.text(),
            };
            let label = if action {
                x.label.clone()
            } else {
                crate::ui::text::fit(&x.label, label_w)
            };
            let mut spans = vec![Span::styled(label, label_style)];
            if !action {
                spans.push(Span::styled(value, th.title()));
                let tag_style = if x.origin == Origin::Own {
                    th.warn()
                } else {
                    th.muted()
                };
                spans.push(Span::styled(tag, tag_style));
            }
            Line::from(spans)
        })
        .collect();
    scroll::render(
        f,
        area,
        th.block(false).title(Span::styled(
            format!(
                " {}: {} ",
                crate::t!("sub.title"),
                app.group_title(&app.sub_name)
            ),
            th.title(),
        )),
        Content::new(
            lines,
            Some(app.sub_cursor.min(fields.len().saturating_sub(1))),
            None,
        )
        .with_mouse(&app.hits, Wheel::Sub, clicks),
        &app.sub_scroll,
        th,
    );
    let text = fields
        .get(app.sub_cursor)
        .map(|x| x.row.explain())
        .unwrap_or_default();
    crate::ui::explain::render(f, foot, &text, None, th);
}
