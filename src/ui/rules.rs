use crate::app::{AppState, RuleItem, Screen};
use crate::model::rule::{builtin_presets, RoutingMode, TrafficMode};
use crate::ui::scroll::{self, Content};
use crate::ui::theme::Theme;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

fn mark(on: bool) -> &'static str {
    if on {
        "[x]"
    } else {
        "[ ]"
    }
}

pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme, ctx: &super::RenderCtx) {
    debug_assert_eq!(app.screen, Screen::Rules);
    let routing = app.config.mode.routing;
    let tun = app.mode == TrafficMode::Tun;
    let presets = builtin_presets();

    let [head, list_area, foot] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(3),
        Constraint::Length(4),
    ])
    .areas(area);

    let (mode_name, mode_text) = match routing {
        RoutingMode::Exclude => ("exclude", crate::t!("rules.mode_exclude")),
        RoutingMode::Include => ("include", crate::t!("rules.mode_include")),
    };
    f.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(format!("{} ", crate::t!("rules.routing_label")), th.muted()),
                Span::styled(mode_name, th.title()),
                Span::styled(format!(" ({mode_text})"), th.text()),
            ]),
            Line::from(Span::styled(
                if tun {
                    crate::t!("rules.traffic_tun")
                } else {
                    crate::t!("rules.traffic_proxy")
                },
                if tun { th.good() } else { th.warn() },
            )),
        ])
        .block(th.block(false).title(Span::styled(
            format!(" {} ", crate::t!("panel.rules")),
            th.title(),
        ))),
        head,
    );

    let items = app.rule_items();
    let rows: Vec<Line> = items
        .iter()
        .map(|item| match item {
            RuleItem::Preset(id) => {
                let p = presets
                    .iter()
                    .find(|p| &p.id == id)
                    .expect("builtin preset");
                let on = app.config.presets.enabled.contains(id);
                let active = p.active_in(routing);
                let has_processes = !p.processes(ctx.windows).is_empty();
                let mut note = String::new();
                if !active {
                    note = format!("  {}", crate::t!("rules.inactive_in", mode = mode_name));
                } else if has_processes && !tun {
                    note = format!("  {}", crate::t!("rules.processes_tun_only"));
                }
                let style = if on && active { th.text() } else { th.muted() };
                Line::from(vec![
                    Span::styled(format!("{} ", mark(on)), th.good()),
                    Span::styled(
                        format!(
                            "{}  {}",
                            crate::t!("rules.preset"),
                            crate::model::rule::preset_title(p)
                        ),
                        style,
                    ),
                    Span::styled(note, th.warn()),
                ])
            }
            RuleItem::Rule(i) => {
                let r = &app.config.rules[*i];
                let inactive_process = r.kind == crate::model::rule::RuleKind::Process && !tun;
                let style = if r.enabled && !inactive_process {
                    th.text()
                } else {
                    th.muted()
                };
                Line::from(vec![
                    Span::styled(format!("{} ", mark(r.enabled)), th.good()),
                    Span::styled(
                        format!("{:<8} {}", r.kind.label(), app.rule_value(r)),
                        style,
                    ),
                    Span::styled(
                        if inactive_process {
                            format!("  {}", crate::t!("rules.rule_tun_only"))
                        } else {
                            String::new()
                        },
                        th.warn(),
                    ),
                ])
            }
        })
        .collect();
    let selected = app.rules_cursor.min(rows.len().saturating_sub(1));
    scroll::render(
        f,
        list_area,
        th.block(false).title(Span::styled(
            format!(" {} ", crate::t!("panel.rules_list")),
            th.title(),
        )),
        Content {
            lines: rows,
            selected: Some(selected),
            context_from: None,
        },
        &app.rules_scroll,
        th,
    );

    // A line of context for the selected item.
    let hint = match items.get(app.rules_cursor.min(items.len().saturating_sub(1))) {
        Some(RuleItem::Preset(id)) => presets
            .iter()
            .find(|p| &p.id == id)
            .map(|p| {
                let names = p.processes(ctx.windows).join(", ");
                let mut text = if names.is_empty() {
                    String::new()
                } else {
                    format!("{} ", crate::t!("rules.processes", names = names))
                };
                if p.block_udp443 && app.vision_in_use() {
                    // First, so the footer (two lines) cannot cut it off.
                    text.push_str(&format!("{} ", crate::t!("rules.vision_note")));
                }
                text.push_str(&crate::model::rule::preset_note(p));
                text
            })
            .unwrap_or_default(),
        _ => String::new(),
    };
    // Only the description of the selected item: the keys are in the bar at the bottom.
    f.render_widget(
        Paragraph::new(Span::styled(hint, th.muted()))
            .wrap(Wrap { trim: false })
            .block(th.block(false)),
        foot,
    );
}
