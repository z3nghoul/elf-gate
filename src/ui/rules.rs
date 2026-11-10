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
        RoutingMode::Exclude => ("exclude", "всё через VPN, кроме правил"),
        RoutingMode::Include => ("include", "через VPN только правила, остальное напрямую"),
    };
    f.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled("Режим маршрутизации: ", th.muted()),
                Span::styled(mode_name, th.title()),
                Span::styled(format!(" ({mode_text})"), th.text()),
            ]),
            Line::from(Span::styled(
                if tun {
                    "Режим трафика: TUN, правила по процессам работают"
                } else {
                    "Режим трафика: PROXY, правила по процессам неактивны (работают только в режиме TUN)"
                },
                if tun { th.good() } else { th.warn() },
            )),
        ])
        .block(Block::bordered().title(Span::styled(" Правила ", th.title()))),
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
                    note = format!("  (неактивен в режиме {mode_name})");
                } else if has_processes && !tun {
                    note = "  (процессы работают только в TUN)".into();
                }
                let style = if on && active { th.text() } else { th.muted() };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", mark(on)), th.good()),
                    Span::styled(format!("пресет  {}", p.title), style),
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
                    Span::styled(format!("{:<8} {}", r.kind.label(), r.value), style),
                    Span::styled(
                        if inactive_process {
                            "  (только в TUN)"
                        } else {
                            ""
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
            .block(Block::bordered().title(Span::styled(" Пресеты и ваши правила ", th.title())))
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
                    format!("процессы: {names}. ")
                };
                text.push_str(&p.note);
                text
            })
            .unwrap_or_default(),
        _ => String::new(),
    };
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(hint, th.muted())),
            Line::from(Span::styled(
                "Space вкл/выкл   a добавить   x удалить   m режим exclude/include   Esc назад",
                th.text(),
            )),
        ])
        .wrap(Wrap { trim: false })
        .block(Block::bordered()),
        foot,
    );
}
