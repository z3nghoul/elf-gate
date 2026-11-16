//! The explanation of the selected row: one fixed place under the list (three lines), so that it
//! does not move when the list scrolls.

use crate::ui::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

/// Rows the box takes: three lines of text and the border.
pub const HEIGHT: u16 = 5;

/// `note` goes on the bottom border (the tray state on the settings screen).
pub fn render(f: &mut Frame, area: Rect, text: &str, note: Option<String>, th: &Theme) {
    let mut block = th.block(false);
    if let Some(note) = note {
        block = block.title_bottom(Line::from(Span::styled(format!(" {note} "), th.muted())));
    }
    let inner_w = area.width.saturating_sub(2) as usize;
    let lines: Vec<Line> = crate::ui::text::wrap(text, inner_w)
        .into_iter()
        .map(|l| Line::from(Span::styled(l, th.info())))
        .collect();
    f.render_widget(Paragraph::new(lines).block(block), area);
}

#[cfg(test)]
mod tests {
    use crate::app::subscription::SubRow;
    use crate::app::SettingId;

    /// The longest text that fits: three lines of the width of an 80-column screen.
    const MAX_LINES: usize = 3;
    const WIDTH_80: usize = 80 - 2;

    #[test]
    fn every_setting_and_subscription_row_is_explained_in_three_lines_in_every_language() {
        for lang in crate::i18n::ALL {
            crate::i18n::bind_thread(lang);
            let texts = SettingId::ALL
                .iter()
                .flat_map(|id| {
                    [false, true].map(|w| (format!("{id:?} windows={w}"), id.explain(w)))
                })
                .chain(SubRow::ALL.iter().map(|r| (format!("{r:?}"), r.explain())));
            for (name, text) in texts {
                assert!(
                    !text.is_empty() && !text.starts_with("explain."),
                    "{lang:?} {name}: `{text}`"
                );
                let lines = crate::ui::text::wrap(&text, WIDTH_80);
                assert!(
                    lines.len() <= MAX_LINES,
                    "{lang:?} {name}: {} lines of 78 columns: {text}",
                    lines.len()
                );
            }
        }
    }

    #[test]
    fn the_rows_on_the_screens_are_all_in_the_list() {
        // A new setting must be added to `SettingId::ALL` (and so to the explanations).
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let app = crate::app::AppState::new(tx);
        for windows in [false, true] {
            for (id, _, _) in app.settings_rows_for(windows) {
                assert!(SettingId::ALL.contains(&id), "{id:?}");
            }
        }
        assert_eq!(SettingId::ALL.len(), 28);
    }
}
