use crate::app::{process_matches, AppState, Popup};
use crate::ui::scroll::{self, Scroll};
use crate::ui::text::wrap;
use crate::ui::theme::Theme;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Clear;
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

/// What is inside the window's border: fixed lines on top (the filter), the body, and fixed
/// lines at the bottom (the keys). When the room is short, the body gives way: the top lines
/// and the keys are always drawn.
struct Dialog {
    title: String,
    border: Style,
    top: Vec<Line<'static>>,
    body: Vec<Line<'static>>,
    /// A selected body line makes the body a scrolling list (the selected line stays visible).
    selected: Option<usize>,
    /// The body takes all the height there is (a long list).
    fill: bool,
    bottom: Vec<Line<'static>>,
}

fn text_lines(text: &str, width: usize, style: Style) -> Vec<Line<'static>> {
    wrap(text, width)
        .into_iter()
        .map(|l| Line::from(Span::styled(l, style)))
        .collect()
}

/// A blank line and the keys.
fn keys_line(text: String, width: usize, th: &Theme) -> Vec<Line<'static>> {
    let mut v = vec![Line::default()];
    v.extend(text_lines(&text, width, th.muted()));
    v
}

/// `area` is the screen without the key bar: the window stays inside it.
pub fn render(f: &mut Frame, area: Rect, app: &AppState, th: &Theme) {
    let Some(popup) = &app.popup else { return };
    let w = area.width.saturating_sub(6).clamp(30, 96).min(area.width);
    let inner_w = w.saturating_sub(2).max(1) as usize;
    let dialog = match popup {
        Popup::Update(release) => update_dialog(release, inner_w, th),
        Popup::Select {
            title,
            options,
            selected,
            ..
        } => Dialog {
            title: app.mask(title),
            border: th.border(true),
            top: Vec::new(),
            body: options
                .iter()
                .map(|o| Line::from(Span::styled(app.mask(o), th.text())))
                .collect(),
            selected: Some(*selected),
            fill: false,
            bottom: keys_line(crate::t!("popup.select_hint"), inner_w, th),
        },
        Popup::Processes {
            items,
            filter,
            selected,
        } => {
            let shown = process_matches(items, filter);
            let mut body: Vec<Line> = shown
                .iter()
                .map(|&i| {
                    let (name, n) = &items[i];
                    let label = if *n > 1 {
                        format!("{name} ({n})")
                    } else {
                        name.clone()
                    };
                    Line::from(Span::styled(app.mask(&label), th.text()))
                })
                .collect();
            let none = body.is_empty();
            if none {
                body.push(Line::from(Span::styled(
                    crate::t!("popup.processes_none"),
                    th.muted(),
                )));
            }
            Dialog {
                title: crate::t!("popup.processes_title"),
                border: th.border(true),
                top: vec![Line::from(vec![
                    Span::styled(
                        format!("{}: ", crate::t!("popup.processes_filter")),
                        th.muted(),
                    ),
                    Span::styled(format!("{filter}_"), th.text()),
                ])],
                body,
                selected: (!none).then_some((*selected).min(shown.len() - 1)),
                fill: true,
                bottom: keys_line(crate::t!("popup.processes_hint"), inner_w, th),
            }
        }
        Popup::Input {
            title,
            buf,
            purpose,
        } => Dialog {
            title: app.mask(title),
            border: th.border(true),
            top: Vec::new(),
            // A link or a subscription URL is typed like a password in privacy mode: the length
            // shows, the content does not (pasting still works).
            body: text_lines(
                &if app.privacy() && *purpose == crate::app::InputPurpose::Link {
                    format!("{}_", "•".repeat(buf.chars().count()))
                } else {
                    format!("{buf}_")
                },
                inner_w,
                th.text(),
            ),
            selected: None,
            fill: false,
            bottom: keys_line(
                if *purpose == crate::app::InputPurpose::Link {
                    format!(
                        "{}; Ctrl+V - {}",
                        crate::t!("popup.input_hint"),
                        crate::t!("hint.paste")
                    )
                } else {
                    crate::t!("popup.input_hint")
                },
                inner_w,
                th,
            ),
        },
        Popup::Confirm { text, kind } => Dialog {
            title: crate::t!("popup.confirm_title"),
            border: th.border(true),
            top: Vec::new(),
            body: text_lines(&app.mask(text), inner_w, th.text()),
            selected: None,
            fill: false,
            bottom: keys_line(
                if matches!(kind, crate::app::ConfirmKind::Paste(_)) {
                    crate::t!("popup.input_hint")
                } else {
                    crate::t!("popup.confirm_hint")
                },
                inner_w,
                th,
            ),
        },
        Popup::Notice(msg) => Dialog {
            title: crate::t!("popup.notice_title"),
            border: th.warn(),
            top: Vec::new(),
            body: text_lines(&app.mask(msg), inner_w, th.warn()),
            selected: None,
            fill: false,
            bottom: keys_line(crate::t!("popup.any_key"), inner_w, th),
        },
        Popup::Error(msg) => Dialog {
            title: crate::t!("popup.error_title"),
            border: th.bad(),
            top: Vec::new(),
            body: text_lines(&app.mask(msg), inner_w, th.bad()),
            selected: None,
            fill: false,
            bottom: keys_line(crate::t!("popup.any_key"), inner_w, th),
        },
    };
    draw(f, area, w, dialog, &app.popup_scroll, th);
}

fn draw(f: &mut Frame, area: Rect, w: u16, d: Dialog, scroll: &Scroll, th: &Theme) {
    let top_h = d.top.len();
    let bottom_h = d.bottom.len();
    // Two rows of margin when the screen is tall enough; on a small one the whole height.
    let max_h = if area.height >= 9 {
        area.height - 2
    } else {
        area.height
    };
    let want = if d.fill {
        max_h as usize
    } else {
        top_h + d.body.len() + bottom_h + 2
    };
    let h = (want as u16).clamp(7.min(max_h), max_h);
    let rect = centered(area, w, h);
    f.render_widget(Clear, rect);
    let inner_h = h.saturating_sub(2) as usize;
    // The keys keep their rows; the top lines come next; the body gets what is left.
    let bottom_rows = bottom_h.min(inner_h);
    let top_rows = top_h.min(inner_h - bottom_rows);
    let body_rows = inner_h - bottom_rows - top_rows;
    let mut block = th
        .block(true)
        .border_style(d.border)
        .title(Span::styled(format!(" {} ", d.title), th.title()));
    scroll.claim(&d.title);
    let total = d.body.len();
    let keep = d.selected.map(|s| (s, s));
    let range = scroll.window(total, body_rows, keep);
    if let Some(text) = scroll::more(&range, total) {
        block = block.title_bottom(
            Line::from(Span::styled(format!(" {text} "), th.muted())).right_aligned(),
        );
    }
    let inner = block.inner(rect);
    f.render_widget(block, rect);
    let [top_area, body_area, bottom_area] = Layout::vertical([
        Constraint::Length(top_rows as u16),
        Constraint::Length(body_rows as u16),
        Constraint::Length(bottom_rows as u16),
    ])
    .areas(inner);
    f.render_widget(
        ratatui::widgets::Paragraph::new(d.top.into_iter().take(top_rows).collect::<Vec<_>>()),
        top_area,
    );
    scroll::draw_lines(f, body_area, d.body, &range, d.selected, th);
    // The last lines of the keys are the ones that matter when there is no room for all.
    let skip = bottom_h - bottom_rows;
    f.render_widget(
        ratatui::widgets::Paragraph::new(d.bottom.into_iter().skip(skip).collect::<Vec<_>>()),
        bottom_area,
    );
}

/// The new version: the notes may be long, so they scroll in the room that is left, while the
/// link and the hint keep their own rows.
fn update_dialog(release: &crate::update::Release, width: usize, th: &Theme) -> Dialog {
    let body = if release.notes.is_empty() {
        text_lines(&crate::t!("popup.update_no_notes"), width, th.muted())
    } else {
        text_lines(&release.notes, width, th.text())
    };
    let mut bottom = vec![Line::default()];
    bottom.extend(text_lines(
        &crate::t!("popup.update_page", url = release.url),
        width,
        th.title(),
    ));
    bottom.push(Line::default());
    bottom.extend(text_lines(
        &crate::t!("popup.update_hint"),
        width,
        th.muted(),
    ));
    Dialog {
        title: crate::t!("popup.update_title", version = release.version),
        border: th.border(true),
        top: Vec::new(),
        body,
        selected: None,
        fill: true,
        bottom,
    }
}
