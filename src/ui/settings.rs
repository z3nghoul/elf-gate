use crate::app::settings::section_of;
use crate::app::{AppState, Screen, SettingId};
use crate::ui::hits::{Rows, Target, Wheel};
use crate::ui::scroll::{self, Content};
use crate::ui::theme::Theme;
use crate::ui::RenderCtx;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

/// One line of the list: a section header (never selected) or a setting row.
pub enum Item {
    Header(crate::app::settings::Section),
    Row(usize),
}

/// The rows with a header before each section.
pub fn layout(rows: &[(SettingId, String, String)]) -> Vec<Item> {
    let mut items = Vec::new();
    let mut last = None;
    for (i, r) in rows.iter().enumerate() {
        let sec = section_of(&r.0);
        if last != Some(sec) {
            items.push(Item::Header(sec));
            last = Some(sec);
        }
        items.push(Item::Row(i));
    }
    items
}

pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme, ctx: &RenderCtx) {
    debug_assert_eq!(app.screen, Screen::Settings);
    let [list_area, foot] = Layout::vertical([
        Constraint::Min(3),
        Constraint::Length(crate::ui::explain::HEIGHT),
    ])
    .areas(area);
    let rows = app.settings_rows_for(ctx.windows);
    let inner_w = list_area.width.saturating_sub(4) as usize;
    // The label column fits the longest label, but leaves room for a value.
    let label_w = rows
        .iter()
        .map(|r| r.1.width())
        .max()
        .unwrap_or(0)
        .min(inner_w.saturating_sub(24))
        + 2;
    let cursor = app.settings_cursor.min(rows.len().saturating_sub(1));
    let mut selected_item = 0;
    let mut context_from = None;
    let mut last_header = None;
    let mut clicks: Vec<scroll::Spot> = Vec::new();
    let lines: Vec<Line> = layout(&rows)
        .iter()
        .enumerate()
        .map(|(n, item)| match item {
            Item::Header(sec) => {
                last_header = Some(n);
                let title = format!("─ {} ", sec.title());
                let fill = "─".repeat(inner_w.saturating_sub(title.width()));
                Line::from(Span::styled(
                    format!("{title}{fill}"),
                    th.border(false)
                        .add_modifier(ratatui::style::Modifier::BOLD),
                ))
            }
            Item::Row(i) => {
                if *i == cursor {
                    selected_item = n;
                    // The first row of a section brings its header into view.
                    context_from = last_header.filter(|h| *h + 1 == n);
                }
                clicks.push(scroll::row(n, Target::Row(Rows::Settings, *i)));
                let (id, label, value) = &rows[*i];
                let value = if app.privacy() && *id == SettingId::Hwid {
                    crate::redact::hwid(value)
                } else if *id == SettingId::PingTimeout {
                    format!("{value} {}", crate::t!("unit.ms"))
                } else if *id == SettingId::PingAuto {
                    if value == "0" {
                        crate::t!("unit.off")
                    } else {
                        format!("{value} {}", crate::t!("unit.s"))
                    }
                } else {
                    app.mask(value)
                };
                Line::from(vec![
                    Span::styled(crate::ui::text::fit(label, label_w), th.text()),
                    Span::styled(value, th.title()),
                ])
            }
        })
        .collect();
    scroll::render(
        f,
        list_area,
        th.block(false).title(Span::styled(
            format!(" {} ", crate::t!("panel.settings")),
            th.title(),
        )),
        Content::new(lines, Some(selected_item), context_from).with_mouse(
            &app.hits,
            Wheel::Settings,
            clicks,
        ),
        &app.settings_scroll,
        th,
    );
    let tray = if app.tray {
        crate::t!("settings.tray_present")
    } else {
        crate::t!("settings.tray_absent")
    };
    let text = rows
        .get(cursor)
        .map(|r| r.0.explain(ctx.windows))
        .unwrap_or_default();
    crate::ui::explain::render(f, foot, &text, Some(tray), th);
}
