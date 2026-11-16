use crate::action::BINDINGS;
use crate::build_info;
use crate::ui::scroll::{self, Content};
use crate::ui::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::Frame;

pub fn render(f: &mut Frame, area: Rect, th: &Theme, scroll: &scroll::Scroll) {
    const KEY_W: usize = 18;
    let desc_w = (area.width as usize).saturating_sub(2 + KEY_W).max(10);
    // A key and its description; a long description continues under itself.
    let entry = |key: String, key_style, desc: String| -> Vec<Line<'static>> {
        crate::ui::text::wrap(&desc, desc_w)
            .into_iter()
            .enumerate()
            .map(|(i, part)| {
                let k = if i == 0 {
                    crate::ui::text::pad(&key, KEY_W)
                } else {
                    " ".repeat(KEY_W)
                };
                Line::from(vec![
                    Span::styled(k, key_style),
                    Span::styled(part, th.text()),
                ])
            })
            .collect()
    };
    let mut lines: Vec<Line> = BINDINGS
        .iter()
        .filter(|b| !b.hidden)
        .flat_map(|b| entry(b.label.to_string(), th.title(), b.desc()))
        .collect();
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        build_info::version_line(),
        th.muted(),
    )));
    lines.push(Line::default());
    lines.extend(entry(
        crate::t!("tag.deprecated"),
        th.warn(),
        crate::t!("help.legend_deprecated"),
    ));
    lines.extend(entry(
        crate::t!("help.legend_grey_key"),
        th.muted(),
        crate::t!("help.legend_grey"),
    ));
    scroll::render(
        f,
        area,
        th.block(false).title(Span::styled(
            format!(" {} ", crate::t!("panel.help")),
            th.title(),
        )),
        Content {
            lines,
            selected: None,
            context_from: None,
        },
        scroll,
        th,
    );
}
