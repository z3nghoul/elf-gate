use crate::app::{AppState, RuleItem, Screen};
use crate::model::rule::{builtin_presets, RoutingMode, TrafficMode};
use crate::ui::theme::Theme;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

fn mark(on: bool) -> &'static str {
    if on {
        "[x]"
    } else {
        "[ ]"
    }
}

pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme) {
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
        .block(Block::bordered().title(Span::styled(
            format!(" {} ", crate::t!("panel.rules")),
            th.title(),
        ))),
        head,
    );

    let items = app.rule_items();
    let rows: Vec<ListItem> = items
        .iter()
        .map(|item| match item {
            RuleItem::Preset(id) => {
                let p = presets
                    .iter()
                    .find(|p| &p.id == id)
                    .expect("builtin preset");
                let on = app.config.presets.enabled.contains(id);
                let active = p.active_in(routing);
                let has_processes = !p.processes(cfg!(windows)).is_empty();
                let mut note = String::new();
                if !active {
                    note = format!("  {}", crate::t!("rules.inactive_in", mode = mode_name));
                } else if has_processes && !tun {
                    note = format!("  {}", crate::t!("rules.processes_tun_only"));
                }
                let style = if on && active { th.text() } else { th.muted() };
                ListItem::new(Line::from(vec![
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
                ]))
            }
            RuleItem::Rule(i) => {
                let r = &app.config.rules[*i];
                let inactive_process = r.kind == crate::model::rule::RuleKind::Process && !tun;
                let style = if r.enabled && !inactive_process {
                    th.text()
                } else {
                    th.muted()
                };
                ListItem::new(Line::from(vec![
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
                ]))
            }
        })
        .collect();
    let mut state = ListState::default();
    state.select(Some(app.rules_cursor.min(rows.len().saturating_sub(1))));
    f.render_stateful_widget(
        List::new(rows)
            .block(Block::bordered().title(Span::styled(
                format!(" {} ", crate::t!("panel.rules_list")),
                th.title(),
            )))
            .highlight_symbol("> ")
            .highlight_style(th.selected()),
        list_area,
        &mut state,
    );

    // A line of context for the selected item.
    let hint = match items.get(app.rules_cursor.min(items.len().saturating_sub(1))) {
        Some(RuleItem::Preset(id)) => presets
            .iter()
            .find(|p| &p.id == id)
            .map(|p| {
                let names = p.processes(cfg!(windows)).join(", ");
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
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(hint, th.muted())),
            Line::from(Span::styled(crate::t!("rules.footer"), th.text())),
        ])
        .wrap(Wrap { trim: false })
        .block(Block::bordered()),
        foot,
    );
}
