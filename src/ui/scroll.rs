//! The one scrolling component: a list with a selection, or plain text, in a bordered block.
//! A screen gives the lines, the selected line and a [`Scroll`] that lives in the application
//! state; the window moves by itself so that the selected line is always visible. When not
//! everything fits, the bottom border says how many lines are hidden ("↑ 3 more / ↓ 5 more").

use super::hits::{HitMap, Target, Wheel};
use super::theme::Theme;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;
use std::cell::Cell;
use std::ops::Range;

/// The position of the window. Drawing updates it (so it is a `Cell`: screens draw from `&AppState`).
#[derive(Debug, Clone, Default)]
pub struct Scroll {
    offset: Cell<usize>,
    /// Rows the window had when it was drawn last: the size of a "page".
    page: Cell<usize>,
    /// One `Scroll` serves every pop-up: a window that is not the owner's starts at the top.
    owner: std::cell::RefCell<String>,
}

impl Scroll {
    /// The window belongs to `key` (a pop-up's title); another owner starts from the top.
    pub fn claim(&self, key: &str) {
        let mut owner = self.owner.borrow_mut();
        if *owner != key {
            *owner = key.to_string();
            self.offset.set(0);
        }
    }

    /// Rows of the last drawn window (at least 1), for PgUp / PgDn.
    pub fn page(&self) -> usize {
        self.page.get().max(1)
    }

    /// Text without a selection: move the top line (clamped when drawn).
    pub fn by(&self, delta: isize) {
        self.offset
            .set(self.offset.get().saturating_add_signed(delta));
    }

    pub fn to_top(&self) {
        self.offset.set(0);
    }

    pub fn to_bottom(&self) {
        self.offset.set(usize::MAX);
    }

    /// The lines to draw. `keep` is an inclusive range of lines that must be visible (the
    /// selected line, and its section header when it is the section's first line).
    pub fn window(
        &self,
        total: usize,
        height: usize,
        keep: Option<(usize, usize)>,
    ) -> Range<usize> {
        self.page.set(height);
        let mut off = self.offset.get().min(total.saturating_sub(height));
        if let Some((a, b)) = keep {
            let b = b.min(total.saturating_sub(1));
            if b >= off + height {
                off = b + 1 - height;
            }
            if a < off {
                off = a;
            }
        }
        self.offset.set(off);
        off..(off + height).min(total)
    }
}

/// "↑ 3 more / ↓ 5 more", or `None` when everything is visible.
pub fn more(range: &Range<usize>, total: usize) -> Option<String> {
    let (up, down) = (range.start, total - range.end);
    match (up, down) {
        (0, 0) => None,
        (0, d) => Some(crate::t!("scroll.down", n = d)),
        (u, 0) => Some(crate::t!("scroll.up", n = u)),
        (u, d) => Some(format!(
            "{} / {}",
            crate::t!("scroll.up", n = u),
            crate::t!("scroll.down", n = d)
        )),
    }
}

/// What to draw in a block.
pub struct Content<'a> {
    pub lines: Vec<Line<'a>>,
    /// The selected line (a `> ` marker and the selection colours); `None` for plain text.
    pub selected: Option<usize>,
    /// Extra lines to keep in view with the selected one: its header, when it is the first
    /// under it.
    pub context_from: Option<usize>,
    /// The mouse: the map the visible rows are registered in and what the wheel turns here.
    pub mouse: Option<(&'a HitMap, Wheel)>,
    /// What a click does on which lines (an item may take several): registered for the part
    /// that is visible.
    pub clicks: Vec<Spot>,
}

/// A clickable part of a list: the lines it is on, the columns (from the left edge of the
/// window: `None` is the whole width) and what a click does. Later ones lie on top.
pub type Spot = (Range<usize>, Option<(u16, u16)>, Target);

/// A whole row of the list.
pub fn row(line: usize, target: Target) -> Spot {
    (line..line + 1, None, target)
}

impl<'a> Content<'a> {
    /// A list or a text the mouse does not act on.
    pub fn new(lines: Vec<Line<'a>>, selected: Option<usize>, context_from: Option<usize>) -> Self {
        Self {
            lines,
            selected,
            context_from,
            mouse: None,
            clicks: Vec::new(),
        }
    }

    /// The wheel turns this window, and the rows answer clicks.
    pub fn with_mouse(mut self, hits: &'a HitMap, wheel: Wheel, clicks: Vec<Spot>) -> Self {
        self.mouse = Some((hits, wheel));
        self.clicks = clicks;
        self
    }
}

/// Draws `block` over `area` and the visible part of the content inside it.
pub fn render(
    f: &mut Frame,
    area: Rect,
    block: Block<'_>,
    content: Content<'_>,
    scroll: &Scroll,
    th: &Theme,
) {
    let inner = block.inner(area);
    let total = content.lines.len();
    let keep = content
        .selected
        .map(|s| (content.context_from.unwrap_or(s).min(s), s));
    let range = scroll.window(total, inner.height as usize, keep);
    let block = match more(&range, total) {
        Some(text) => block.title_bottom(
            Line::from(Span::styled(format!(" {text} "), th.muted())).right_aligned(),
        ),
        None => block,
    };
    f.render_widget(block, area);
    draw_lines(f, inner, content.lines, &range, content.selected, th);
    if let Some((hits, wheel)) = content.mouse {
        hits.wheel(area, wheel);
        for (lines, columns, target) in content.clicks {
            let (from, to) = (lines.start.max(range.start), lines.end.min(range.end));
            if from >= to {
                continue;
            }
            let (dx, w) = columns.unwrap_or((0, inner.width));
            let w = w.min(inner.width.saturating_sub(dx));
            let rect = Rect::new(
                inner.x + dx,
                inner.y + (from - range.start) as u16,
                w,
                (to - from) as u16,
            );
            hits.click(rect, target);
            hits.light(f, rect, th);
        }
    }
}

/// The lines of `range`, with the marker and the selection colours when something is selected.
pub fn draw_lines(
    f: &mut Frame,
    inner: Rect,
    lines: Vec<Line<'_>>,
    range: &Range<usize>,
    selected: Option<usize>,
    th: &Theme,
) {
    let visible: Vec<Line> = lines
        .into_iter()
        .enumerate()
        .skip(range.start)
        .take(range.len())
        .map(|(i, mut line)| {
            if selected.is_some() {
                let on = Some(i) == selected;
                line.spans
                    .insert(0, Span::raw(if on { "> " } else { "  " }));
                if on {
                    line = line.style(th.selected());
                    // Muted text on the selection may be too pale: the theme says what to use.
                    if th.muted_on_selection != th.muted {
                        for span in &mut line.spans {
                            if span.style.fg == Some(th.muted) {
                                span.style.fg = Some(th.muted_on_selection);
                            }
                        }
                    }
                }
            }
            line
        })
        .collect();
    f.render_widget(Paragraph::new(visible), inner);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_selected_line_pulls_the_window_after_it() {
        let s = Scroll::default();
        assert_eq!(s.window(100, 10, Some((0, 0))), 0..10);
        assert_eq!(s.window(100, 10, Some((12, 12))), 3..13);
        assert_eq!(s.window(100, 10, Some((5, 5))), 3..13);
        assert_eq!(s.window(100, 10, Some((99, 99))), 90..100);
        assert_eq!(s.page(), 10);
    }

    #[test]
    fn the_header_stays_with_the_first_row_of_its_section() {
        let s = Scroll::default();
        s.window(50, 10, Some((30, 30)));
        assert_eq!(s.window(50, 10, Some((20, 21))), 20..30);
    }

    #[test]
    fn text_scrolls_by_lines_and_stays_inside() {
        let s = Scroll::default();
        s.by(4);
        assert_eq!(s.window(30, 10, None), 4..14);
        s.to_bottom();
        assert_eq!(s.window(30, 10, None), 20..30);
        s.by(5);
        assert_eq!(s.window(30, 10, None), 20..30);
        s.to_top();
        assert_eq!(s.window(5, 10, None), 0..5);
    }
}
