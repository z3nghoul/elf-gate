//! The check screen: one block per check (state, title, what was found) and, for a problem,
//! the line of what to do. The cursor is on a check; Enter does what it offers.

use crate::app::AppState;
use crate::diag::State;
use crate::ui::scroll::{self, Content};
use crate::ui::theme::Theme;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::Frame;

fn state_style(state: State, th: &Theme) -> Style {
    match state {
        State::Ok => th.good(),
        State::Problem => th.bad(),
        State::Running => th.warn(),
        State::Waiting | State::Skipped => th.muted(),
    }
}

pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme) {
    let width = (area.width as usize).saturating_sub(4).max(10);
    let label_w = app
        .diag
        .iter()
        .map(|r| unicode_width::UnicodeWidthStr::width(r.state.label().as_str()))
        .max()
        .unwrap_or(0);
    let mut lines: Vec<Line> = crate::ui::text::wrap(&crate::t!("diag.intro"), width)
        .into_iter()
        .map(|l| Line::from(Span::styled(l, th.muted())))
        .collect();
    lines.push(Line::default());
    let mut selected = 0;
    let mut first = 0;
    for (i, r) in app.diag.iter().enumerate() {
        if i == app.diag_cursor {
            selected = lines.len();
            first = lines.len();
        }
        let tag = crate::ui::text::pad(&r.state.label(), label_w);
        let head = format!("{}  {}", r.id.title(), r.detail);
        let indent = label_w + 2;
        for (n, part) in
            crate::ui::text::wrap(&app.mask(&head), width.saturating_sub(indent).max(10))
                .into_iter()
                .enumerate()
        {
            let lead = if n == 0 {
                Span::styled(format!("{tag}  "), state_style(r.state, th))
            } else {
                Span::raw(" ".repeat(indent))
            };
            lines.push(Line::from(vec![lead, Span::styled(part, th.text())]));
        }
        if let Some(todo) = &r.todo {
            for part in crate::ui::text::wrap(
                &app.mask(&format!("-> {todo}")),
                width.saturating_sub(indent).max(10),
            ) {
                lines.push(Line::from(vec![
                    Span::raw(" ".repeat(indent)),
                    Span::styled(part, th.warn()),
                ]));
            }
        }
    }
    scroll::render(
        f,
        area,
        th.block(false).title(Span::styled(
            format!(" {} ", crate::t!("panel.diag")),
            th.title(),
        )),
        Content {
            lines,
            selected: Some(selected),
            context_from: Some(first),
        },
        &app.diag_scroll,
        th,
    );
}
