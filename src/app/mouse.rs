//! The mouse: a click is the same step as the key it stands for, so there is no logic of its
//! own here. `ui::hits` says what is under the pointer (the screens register it every frame);
//! this turns it into the existing actions, selections and keys.

use super::{AppState, Focus, Popup, Screen};
use crate::action::Action;
use crate::ui::hits::{Rows, Target, Wheel};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use std::time::{Duration, Instant};

/// Two clicks on the same element this close are a double click.
pub const DOUBLE_CLICK: Duration = Duration::from_millis(400);

/// Rows one turn of the wheel moves.
const WHEEL_STEP: isize = 3;

impl AppState {
    /// One mouse event. Returns whether the screen must be drawn again: moving the pointer
    /// inside the same element changes nothing.
    pub fn handle_mouse(&mut self, ev: MouseEvent) -> bool {
        if !self.config.ui.mouse {
            return false;
        }
        match ev.kind {
            MouseEventKind::Moved => self.hits.hover_at(ev.column, ev.row),
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(target) = self.hits.target_at(ev.column, ev.row) {
                    self.click(target);
                }
                true
            }
            MouseEventKind::ScrollUp => self.wheel(ev.column, ev.row, true),
            MouseEventKind::ScrollDown => self.wheel(ev.column, ev.row, false),
            _ => false,
        }
    }

    fn click(&mut self, target: Target) {
        let now = Instant::now();
        let double = matches!(
            self.last_click,
            Some((at, prev)) if prev == target && now.duration_since(at) <= DOUBLE_CLICK
        );
        // The third click of a quick series starts a new pair.
        self.last_click = if double { None } else { Some((now, target)) };
        match target {
            Target::Key(code, mods) => self.handle_key(KeyEvent::new(code, mods)),
            Target::Action(action) => self.handle_action(action),
            Target::Panel(focus) => {
                if self.screen == Screen::Main && self.popup.is_none() {
                    self.focus = focus;
                }
            }
            Target::Row(rows, index) => self.click_row(rows, index, double),
            Target::RowAction(rows, index, action) => {
                self.select_row(rows, index);
                self.handle_action(action);
            }
            Target::Pick(rows, index) => {
                self.select_row(rows, index);
                self.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
            }
        }
    }

    /// Puts the cursor of the list on the row; `true` when it already was there.
    fn select_row(&mut self, rows: Rows, index: usize) -> bool {
        match rows {
            Rows::Servers => {
                let was = self.selected == index && self.focus == Focus::Servers;
                self.selected = index;
                self.focus = Focus::Servers;
                was
            }
            Rows::Rules => std::mem::replace(&mut self.rules_cursor, index) == index,
            Rows::Settings => std::mem::replace(&mut self.settings_cursor, index) == index,
            Rows::Sub => std::mem::replace(&mut self.sub_cursor, index) == index,
            Rows::Diag => std::mem::replace(&mut self.diag_cursor, index) == index,
            Rows::Select => match &mut self.popup {
                Some(Popup::Select { selected, .. }) => std::mem::replace(selected, index) == index,
                _ => false,
            },
            Rows::Process => match &mut self.popup {
                Some(Popup::Processes { selected, .. }) => {
                    std::mem::replace(selected, index) == index
                }
                _ => false,
            },
        }
    }

    /// A click on a row selects it; on the selected row (or the second click of a double
    /// click) it does what Enter does there. The rules screen only selects: its check box has
    /// a target of its own.
    fn click_row(&mut self, rows: Rows, index: usize, double: bool) {
        let already = self.select_row(rows, index);
        if (already || double) && rows != Rows::Rules {
            self.handle_action(Action::Enter);
        }
    }

    fn wheel(&mut self, x: u16, y: u16, up: bool) -> bool {
        let Some(wheel) = self.hits.wheel_at(x, y) else {
            return false;
        };
        let delta = if up { -WHEEL_STEP } else { WHEEL_STEP };
        match wheel {
            // A list with a selection scrolls by moving the selection: the window follows it.
            Wheel::Servers => self.move_selection(delta),
            Wheel::Logs => self.scroll_logs(up, WHEEL_STEP as usize),
            Wheel::Rules => self.rules_move(delta),
            Wheel::Settings => self.settings_move(delta),
            Wheel::Sub => self.sub_move(delta),
            Wheel::Diag => {
                let last = self.diag.len().saturating_sub(1) as isize;
                self.diag_cursor = (self.diag_cursor as isize + delta).clamp(0, last) as usize;
            }
            Wheel::Help => self.help_scroll.by(delta),
            Wheel::Popup => self.wheel_popup(delta),
        }
        true
    }

    fn wheel_popup(&mut self, delta: isize) {
        let moved = |at: usize, len: usize| {
            (at as isize + delta).clamp(0, len.saturating_sub(1) as isize) as usize
        };
        match &mut self.popup {
            Some(Popup::Select {
                selected, options, ..
            }) => *selected = moved(*selected, options.len()),
            Some(Popup::Processes {
                selected,
                items,
                filter,
            }) => *selected = moved(*selected, super::process_matches(items, filter).len()),
            Some(_) => self.popup_scroll.by(delta),
            None => {}
        }
    }
}
