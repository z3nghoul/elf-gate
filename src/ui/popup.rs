use crate::app::{AppState, Popup};
use crate::ui::theme::Theme;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph, Wrap};
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
    if let Popup::Update(release) = popup {
        render_update(f, area, w, release, th);
        return;
    }
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
        // Drawn apart above.
        Popup::Update(_) => return,
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
            th.block(false)
                .title(Span::styled(format!(" {title} "), th.title()))
                .border_style(border),
        ),
        rect,
    );
}

/// The new version: the notes may be long, so they get the room that is left and are cut at the
/// bottom, while the link and the hint keep their own rows.
fn render_update(f: &mut Frame, area: Rect, w: u16, release: &crate::update::Release, th: &Theme) {
    let rect = centered(area, w, area.height.saturating_sub(2).min(24));
    let block = th
        .block(false)
        .title(Span::styled(
            format!(
                " {} ",
                crate::t!("popup.update_title", version = release.version)
            ),
            th.title(),
        ))
        .border_style(th.border(true));
    let inner = block.inner(rect);
    f.render_widget(Clear, rect);
    f.render_widget(block, rect);
    let [notes, foot] = Layout::vertical([Constraint::Min(1), Constraint::Length(5)]).areas(inner);
    let text = if release.notes.is_empty() {
        Line::from(Span::styled(crate::t!("popup.update_no_notes"), th.muted())).into()
    } else {
        ratatui::text::Text::from(
            release
                .notes
                .lines()
                .map(|l| Line::from(Span::styled(l.to_string(), th.text())))
                .collect::<Vec<_>>(),
        )
    };
    f.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), notes);
    f.render_widget(
        Paragraph::new(vec![
            Line::default(),
            Line::from(Span::styled(
                crate::t!("popup.update_page", url = release.url),
                th.title(),
            )),
            Line::default(),
            Line::from(Span::styled(crate::t!("popup.update_hint"), th.muted())),
        ])
        .wrap(Wrap { trim: false }),
        foot,
    );
}
