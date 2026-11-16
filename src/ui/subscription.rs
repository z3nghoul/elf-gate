//! The screen of one subscription.

use crate::app::subscription::{Origin, SubRow};
use crate::app::AppState;
use crate::ui::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState};
use ratatui::Frame;

pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme) {
    let fields = app.sub_fields();
    let label_w = fields
        .iter()
        .map(|x| unicode_width::UnicodeWidthStr::width(x.label.as_str()))
        .max()
        .unwrap_or(0)
        + 2;
    let items: Vec<ListItem> = fields
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
            ListItem::new(Line::from(spans))
        })
        .collect();
    let mut state = ListState::default();
    state.select(Some(app.sub_cursor.min(fields.len().saturating_sub(1))));
    f.render_stateful_widget(
        List::new(items)
            .block(th.block(false).title(Span::styled(
                format!(
                    " {}: {} ",
                    crate::t!("sub.title"),
                    app.group_title(&app.sub_name)
                ),
                th.title(),
            )))
            .highlight_symbol("> ")
            .highlight_style(th.selected()),
        area,
        &mut state,
    );
}
