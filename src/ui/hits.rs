//! Where the mouse can act. Every frame the screens register the rectangles of what can be
//! clicked (a key in the key bar, a row, a button) and of what scrolls; the map is rebuilt with
//! each frame, so it always describes what is on the screen. A click takes the topmost
//! rectangle: what is drawn later (a dialog) covers what is under it. A click is turned into
//! the same step as the key would do (see `AppState::handle_mouse`): the mouse has no logic
//! of its own.

use crate::action::Action;
use crate::app::Focus;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::layout::Rect;
use std::cell::{Cell, RefCell};

/// A list a click can pick a row of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rows {
    Servers,
    Rules,
    Settings,
    Sub,
    Diag,
    /// The options of a selection dialog.
    Select,
    /// The filtered programs of the process dialog.
    Process,
}

/// A list or a text the wheel scrolls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wheel {
    Servers,
    Logs,
    Rules,
    Settings,
    Help,
    Sub,
    Diag,
    /// The list or the text of the open dialog.
    Popup,
}

/// What a click does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// As if the key were pressed (a key of the bar, a button of a dialog).
    Key(KeyCode, KeyModifiers),
    /// The key bound to the action, on the current screen.
    Action(Action),
    /// The focus goes to the panel.
    Panel(Focus),
    /// Select the row; a click on the selected row does what Enter does.
    Row(Rows, usize),
    /// Select the row and do the action (the arrow of a group, the check box of a rule).
    RowAction(Rows, usize, Action),
    /// The row of a dialog list: choose it and apply, as Enter does.
    Pick(Rows, usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Click(Target),
    Wheel(Wheel),
    /// Takes the click and does nothing: a dialog does not let it through to what is under it.
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    pub rect: Rect,
    pub kind: Kind,
}

#[derive(Debug, Default)]
pub struct HitMap {
    hits: RefCell<Vec<Hit>>,
    /// The clickable rectangle under the pointer (the screens draw it lit).
    hover: Cell<Option<Rect>>,
}

fn contains(r: Rect, x: u16, y: u16) -> bool {
    x >= r.x && x < r.x + r.width && y >= r.y && y < r.y + r.height
}

impl HitMap {
    /// A new frame starts: the old rectangles are gone.
    pub fn begin(&self) {
        self.hits.borrow_mut().clear();
    }

    fn add(&self, rect: Rect, kind: Kind) {
        if rect.width > 0 && rect.height > 0 {
            self.hits.borrow_mut().push(Hit { rect, kind });
        }
    }

    pub fn click(&self, rect: Rect, target: Target) {
        self.add(rect, Kind::Click(target));
    }

    pub fn wheel(&self, rect: Rect, wheel: Wheel) {
        self.add(rect, Kind::Wheel(wheel));
    }

    pub fn block(&self, rect: Rect) {
        self.add(rect, Kind::Block);
    }

    /// The topmost rectangle with the point in it.
    pub fn at(&self, x: u16, y: u16) -> Option<Hit> {
        self.hits
            .borrow()
            .iter()
            .rev()
            .find(|h| contains(h.rect, x, y))
            .copied()
    }

    /// What a click at the point does (`None`: nothing, or a dialog swallows it).
    pub fn target_at(&self, x: u16, y: u16) -> Option<Target> {
        // A click goes to the topmost rectangle that takes clicks; a wheel area under it
        // does not matter.
        self.hits
            .borrow()
            .iter()
            .rev()
            .filter(|h| contains(h.rect, x, y))
            .find_map(|h| match h.kind {
                Kind::Click(t) => Some(Some(t)),
                Kind::Block => Some(None),
                Kind::Wheel(_) => None,
            })
            .flatten()
    }

    /// The list or text the wheel turns at the point.
    pub fn wheel_at(&self, x: u16, y: u16) -> Option<Wheel> {
        self.hits
            .borrow()
            .iter()
            .rev()
            .filter(|h| contains(h.rect, x, y))
            .find_map(|h| match h.kind {
                Kind::Wheel(w) => Some(Some(w)),
                Kind::Block => Some(None),
                Kind::Click(_) => None,
            })
            .flatten()
    }

    /// The pointer moved to the point. `true` when the lit element changed (only then the
    /// screen is drawn again).
    pub fn hover_at(&self, x: u16, y: u16) -> bool {
        // The topmost element that takes clicks; a panel is not lit, only what is in it.
        let now = self
            .hits
            .borrow()
            .iter()
            .rev()
            .find(|h| contains(h.rect, x, y) && !matches!(h.kind, Kind::Wheel(_)))
            .and_then(|h| match h.kind {
                Kind::Click(Target::Panel(_)) | Kind::Block | Kind::Wheel(_) => None,
                Kind::Click(_) => Some(h.rect),
            });
        self.set_hover(now)
    }

    /// Lights `rect` (or nothing); `true` when it changed.
    pub fn set_hover(&self, rect: Option<Rect>) -> bool {
        let changed = self.hover.get() != rect;
        self.hover.set(rect);
        changed
    }

    /// Lights the row `rect` when the pointer is on it (and the mouse is on).
    pub fn light(&self, f: &mut ratatui::Frame, rect: Rect, th: &crate::ui::theme::Theme) {
        if self.is_hover(rect) {
            f.buffer_mut().set_style(rect, th.row_hover());
        }
    }

    /// Is `rect` the lit element?
    pub fn is_hover(&self, rect: Rect) -> bool {
        self.hover.get() == Some(rect)
    }

    /// Where a target is on the screen (tests click on it).
    #[cfg(test)]
    pub fn find(&self, target: Target) -> Option<Rect> {
        self.hits
            .borrow()
            .iter()
            .rev()
            .find(|h| h.kind == Kind::Click(target))
            .map(|h| h.rect)
    }

    #[cfg(test)]
    pub fn count(&self) -> usize {
        self.hits.borrow().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(x: u16, y: u16, w: u16, h: u16) -> Rect {
        Rect::new(x, y, w, h)
    }

    #[test]
    fn a_click_hits_the_row_and_misses_the_space_around() {
        let m = HitMap::default();
        m.click(r(2, 3, 10, 1), Target::Row(Rows::Servers, 4));
        assert_eq!(m.target_at(5, 3), Some(Target::Row(Rows::Servers, 4)));
        assert_eq!(m.target_at(12, 3), None, "right of the row");
        assert_eq!(m.target_at(5, 4), None, "below the row");
        assert_eq!(m.target_at(1, 3), None, "left of the row");
    }

    #[test]
    fn what_is_drawn_later_covers_what_is_under_it() {
        let m = HitMap::default();
        m.click(r(0, 0, 40, 10), Target::Panel(Focus::Servers));
        m.click(r(2, 2, 10, 1), Target::Row(Rows::Servers, 0));
        // A dialog: it swallows the clicks on its body, its button still works.
        m.block(r(0, 0, 40, 10));
        m.block(r(10, 3, 20, 4));
        m.click(
            r(12, 5, 6, 1),
            Target::Key(KeyCode::Enter, KeyModifiers::NONE),
        );
        assert_eq!(
            m.target_at(13, 5),
            Some(Target::Key(KeyCode::Enter, KeyModifiers::NONE))
        );
        assert_eq!(m.target_at(15, 4), None, "the dialog body does nothing");
        assert_eq!(
            m.target_at(3, 2),
            None,
            "the row under the dialog is not clicked"
        );
    }

    #[test]
    fn a_new_frame_forgets_the_old_rectangles() {
        let m = HitMap::default();
        m.click(r(0, 0, 5, 1), Target::Panel(Focus::Logs));
        m.begin();
        assert_eq!(m.count(), 0);
        assert_eq!(m.target_at(1, 0), None);
    }

    #[test]
    fn the_wheel_finds_the_list_under_the_pointer_not_the_focused_one() {
        let m = HitMap::default();
        m.wheel(r(0, 0, 20, 10), Wheel::Servers);
        m.wheel(r(0, 10, 20, 10), Wheel::Logs);
        assert_eq!(m.wheel_at(3, 12), Some(Wheel::Logs));
        assert_eq!(m.wheel_at(3, 2), Some(Wheel::Servers));
        assert_eq!(m.wheel_at(30, 2), None);
        m.block(r(0, 0, 20, 20));
        assert_eq!(m.wheel_at(3, 2), None, "a dialog covers the lists");
    }

    #[test]
    fn hover_changes_only_when_the_lit_element_changes() {
        let m = HitMap::default();
        m.click(r(0, 0, 10, 1), Target::Row(Rows::Servers, 0));
        m.click(r(0, 1, 10, 1), Target::Row(Rows::Servers, 1));
        assert!(m.hover_at(2, 0));
        assert!(!m.hover_at(5, 0), "the same row: no new frame");
        assert!(m.is_hover(r(0, 0, 10, 1)));
        assert!(m.hover_at(5, 1));
        assert!(m.hover_at(50, 5), "left every element: the light goes out");
        assert!(!m.is_hover(r(0, 1, 10, 1)));
    }
}
