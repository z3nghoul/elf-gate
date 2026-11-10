use crate::app::{AppState, Popup};
use crate::ui::theme::Theme;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};
use ratatui::Frame;

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let [v] = Layout::vertical([Constraint::Length(h)])
        .flex(Flex::Center)
        .areas(area);
    let [r] = Layout::horizontal([Constraint::Length(w)])
        .flex(Flex::Center)
        .areas(v);
    r
}

pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme) {
    let Some(popup) = &app.popup else { return };
    let w = area.width.saturating_sub(6).clamp(30, 96);
    let (title, lines, border) = match popup {
        Popup::Select {
            title,
            options,
            selected,
            ..
        } => {
            let mut lines: Vec<Line> = options
                .iter()
                .map(|o| app.mask(o))
                .enumerate()
                .map(|(i, o)| {
                    if i == *selected {
                        Line::from(Span::styled(format!("> {o}"), th.selected()))
                    } else {
                        Line::from(Span::styled(format!("  {o}"), th.text()))
                    }
                })
                .collect();
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                crate::t!("popup.select_hint"),
                th.muted(),
            )));
            (app.mask(title), lines, th.border(true))
        }
        Popup::Input {
            title,
            buf,
            purpose,
        } => (
            app.mask(title),
            vec![
                Line::from(Span::styled(
                    // A link or a subscription URL is typed like a password in privacy mode:
                    // the length shows, the content does not (pasting still works).
                    if app.privacy() && *purpose == crate::app::InputPurpose::Link {
                        format!("{}_", "•".repeat(buf.chars().count()))
                    } else {
                        format!("{buf}_")
                    },
                    th.text(),
                )),
                Line::default(),
                Line::from(Span::styled(crate::t!("popup.input_hint"), th.muted())),
            ],
            th.border(true),
        ),
        Popup::Confirm { text, .. } => (
            crate::t!("popup.confirm_title"),
            vec![
                Line::from(Span::styled(app.mask(text), th.text())),
                Line::default(),
                Line::from(Span::styled(crate::t!("popup.confirm_hint"), th.muted())),
            ],
            th.border(true),
        ),
        Popup::Notice(msg) => {
            let mut lines: Vec<Line> = msg
                .lines()
                .map(|l| Line::from(Span::styled(app.mask(l), th.warn())))
                .collect();
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                crate::t!("popup.any_key"),
                th.muted(),
            )));
            (crate::t!("popup.notice_title"), lines, th.warn())
        }
        Popup::Error(msg) => {
            let mut lines: Vec<Line> = msg
                .lines()
                .map(|l| Line::from(Span::styled(app.mask(l), th.bad())))
                .collect();
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                crate::t!("popup.any_key"),
                th.muted(),
            )));
            (crate::t!("popup.error_title"), lines, th.bad())
        }
    };
    // Count wrapped lines, not just newlines: install commands are long.
    let inner = w.saturating_sub(2).max(1);
    let wrapped: u16 = lines
        .iter()
        .map(|l| (l.width() as u16).div_ceil(inner).max(1))
        .sum();
    let h = (wrapped + 2).clamp(7, area.height.saturating_sub(2));
    let rect = centered(area, w, h);
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::bordered()
                .title(Span::styled(format!(" {title} "), th.title()))
                .border_style(border),
        ),
        rect,
    );
}
