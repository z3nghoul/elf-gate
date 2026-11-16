//! Long content on the smallest screen (80x24): the windows stay inside it, the keys stay visible.

use super::{tests_support, RenderCtx};
use crate::action::Action;
use crate::app::{AppState, Popup, Screen};
use crate::platform::mock::MockTunHost;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::sync::Arc;
use tokio::sync::mpsc::unbounded_channel;

fn app() -> AppState {
    let (tx, _rx) = unbounded_channel();
    AppState::with_demo(tx, crate::test_support::config_ru())
}

fn draw(app: &mut AppState) -> String {
    tests_support::draw(80, 24, app)
}

fn press(a: &mut AppState, code: KeyCode) {
    a.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
}

#[tokio::test]
async fn help_on_80x24_top_and_bottom() {
    let mut a = app();
    a.screen = Screen::Help;
    insta::assert_snapshot!("scroll_help_80x24_top", draw(&mut a));
    a.handle_action(Action::Bottom);
    insta::assert_snapshot!("scroll_help_80x24_bottom", draw(&mut a));
}

#[tokio::test]
async fn settings_on_80x24_linux_and_windows_top_and_bottom() {
    for windows in [false, true] {
        let mut a = app();
        a.screen = Screen::Settings;
        let sfx = if windows { "windows" } else { "linux" };
        let ctx = RenderCtx::new(windows, &a.config.ui, super::theme::ColorMode::TrueColor);
        insta::assert_snapshot!(
            format!("scroll_settings_80x24_top_{sfx}"),
            tests_support::draw_on(80, 24, &mut a, &ctx)
        );
        a.handle_action(Action::Bottom);
        insta::assert_snapshot!(
            format!("scroll_settings_80x24_bottom_{sfx}"),
            tests_support::draw_on(80, 24, &mut a, &ctx)
        );
    }
}

#[tokio::test]
async fn process_picker_on_80x24() {
    let mut a = app();
    let host = MockTunHost {
        processes: (0..200)
            .map(|i| format!("proc{:03}", (i * 7) % 150))
            .collect(),
        ..MockTunHost::healthy()
    };
    a = a.with_tun_host(Arc::new(host));
    a.screen = Screen::Rules;
    a.handle_action(Action::Add);
    press(&mut a, KeyCode::Enter);
    assert!(matches!(a.popup, Some(Popup::Processes { .. })));
    insta::assert_snapshot!("scroll_processes_80x24_top", draw(&mut a));
    press(&mut a, KeyCode::End);
    insta::assert_snapshot!("scroll_processes_80x24_end", draw(&mut a));
    press(&mut a, KeyCode::Home);
    for c in "proc14".chars() {
        press(&mut a, KeyCode::Char(c));
    }
    insta::assert_snapshot!("scroll_processes_80x24_filtered", draw(&mut a));
}

#[tokio::test]
async fn popups_stay_inside_a_tiny_screen_and_keep_their_keys() {
    let mut a = app();
    a.popup = Some(Popup::Error("long text ".repeat(60)));
    // Below the supported minimum the "too small" message takes over, so 60x24 is the floor.
    let out = tests_support::draw(60, 24, &mut a);
    assert!(out.lines().count() == 24, "{out}");
    assert!(out.contains("любая клавиша"), "{out}");
}
