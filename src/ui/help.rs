use crate::action::BINDINGS;
use crate::build_info;
use crate::ui::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

pub fn render(f: &mut Frame, area: Rect, th: &Theme) {
    let mut lines: Vec<Line> = BINDINGS
        .iter()
        .filter(|b| !b.hidden)
        .map(|b| {
            Line::from(vec![
                Span::styled(format!("{:<18}", b.label), th.title()),
                Span::styled(b.desc(), th.text()),
            ])
        })
        .collect();
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        build_info::version_line(),
        th.muted(),
    )));
    lines.push(Line::default());
    lines.push(Line::from(vec![
        Span::styled(format!("{:<18}", crate::t!("tag.deprecated")), th.warn()),
        Span::styled(crate::t!("help.legend_deprecated"), th.text()),
    ]));
    lines.push(Line::from(vec![
        Span::styled(
            format!("{:<18}", crate::t!("help.legend_grey_key")),
            th.muted(),
        ),
        Span::styled(crate::t!("help.legend_grey"), th.text()),
    ]));
    f.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(Span::styled(
            format!(" {} ", crate::t!("panel.help")),
            th.title(),
        ))),
        area,
    );
}
