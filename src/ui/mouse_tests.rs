//! The mouse: what is registered for a frame, and what a click, the wheel and the pointer do.
//! A click must make the same change of state as the key it stands for.

use super::hits::{Rows, Target, Wheel};
use super::tests_support::draw;
use crate::action::Action;
use crate::app::tests::view_with;
use crate::app::{AppState, ConfirmKind, Focus, LinkState, Popup, Screen};
use crate::event::{Level, LinkEvent, LogLine};
use crate::proto::{Cmd, Setting, Update};
use crossterm::event::{KeyCode, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

const A: &str = "vless://u@h.example.com:443?security=reality&sni=x.org&pbk=K&sid=ab&fp=chrome#R1";
const B: &str = "vless://u@h2.example.com:443?security=tls&sni=h2.example.com#Two";

fn app() -> (AppState, UnboundedReceiver<Cmd>) {
    let (tx, rx) = unbounded_channel();
    let mut a = AppState::new(tx);
    a.apply_view(view_with(&[A, B]));
    a.link = LinkState::Up;
    // The manual group header is row 0, the servers are rows 1 and 2.
    a.selected = 1;
    (a, rx)
}

fn sent(rx: &mut UnboundedReceiver<Cmd>) -> Vec<Cmd> {
    let mut v = Vec::new();
    while let Ok(c) = rx.try_recv() {
        v.push(c);
    }
    v
}

fn centre(r: Rect) -> (u16, u16) {
    (r.x + r.width / 2, r.y + r.height / 2)
}

fn mouse(kind: MouseEventKind, (column, row): (u16, u16)) -> MouseEvent {
    MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

/// Draws the screen (so the map is there) and clicks the middle of `target`.
fn click_on(a: &mut AppState, target: Target) -> bool {
    draw(100, 30, a);
    let at = a
        .hits
        .find(target)
        .unwrap_or_else(|| panic!("{target:?} is not on the screen"));
    a.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), centre(at)))
}

fn press(a: &mut AppState, code: KeyCode) {
    a.handle_key(crossterm::event::KeyEvent::new(code, KeyModifiers::NONE));
}

#[tokio::test]
async fn one_click_selects_a_server_and_the_second_connects_like_enter() {
    let (mut a, mut rx) = app();
    click_on(&mut a, Target::Row(Rows::Servers, 2));
    assert_eq!(a.selected, 2);
    assert!(
        sent(&mut rx).is_empty(),
        "a click on another row only selects"
    );
    // The click on the selected row does what Enter does.
    click_on(&mut a, Target::Row(Rows::Servers, 2));
    assert_eq!(sent(&mut rx), vec![Cmd::Connect(2)]);

    let (mut k, mut krx) = app();
    k.selected = 2;
    press(&mut k, KeyCode::Enter);
    assert_eq!(
        sent(&mut krx),
        vec![Cmd::Connect(2)],
        "the key does the same"
    );
}

#[tokio::test]
async fn a_double_click_on_a_row_connects_even_when_the_row_was_not_selected() {
    let (mut a, mut rx) = app();
    a.focus = Focus::Logs; // the click also gives the panel the focus
    a.selected = 1;
    click_on(&mut a, Target::Row(Rows::Servers, 2));
    assert!(sent(&mut rx).is_empty());
    // The same row again within the double-click time: the first click selected it already.
    a.last_click = Some((std::time::Instant::now(), Target::Row(Rows::Servers, 2)));
    click_on(&mut a, Target::Row(Rows::Servers, 2));
    assert_eq!(sent(&mut rx), vec![Cmd::Connect(2)]);
    // Two slow clicks are not a double click.
    let (mut b, mut brx) = app();
    b.focus = Focus::Logs;
    click_on(&mut b, Target::Row(Rows::Servers, 2));
    b.focus = Focus::Logs;
    b.last_click = Some((
        std::time::Instant::now() - std::time::Duration::from_millis(900),
        Target::Row(Rows::Servers, 2),
    ));
    click_on(&mut b, Target::Row(Rows::Servers, 2));
    assert!(sent(&mut brx).is_empty());
}

#[tokio::test]
async fn the_arrow_of_a_group_folds_it_and_a_click_on_the_header_selects_it() {
    let (mut a, _rx) = app();
    assert!(!a.subs[0].collapsed);
    click_on(&mut a, Target::RowAction(Rows::Servers, 0, Action::Fold));
    assert!(a.subs[0].collapsed, "as the left arrow does");
    assert_eq!(a.selected, 0);
}

#[tokio::test]
async fn a_click_on_a_panel_gives_it_the_focus() {
    let (mut a, _rx) = app();
    assert_eq!(a.focus, Focus::Servers);
    click_on(&mut a, Target::Panel(Focus::Logs));
    assert_eq!(a.focus, Focus::Logs);
    click_on(&mut a, Target::Panel(Focus::Details));
    assert_eq!(a.focus, Focus::Details);
}

#[tokio::test]
async fn a_key_of_the_bar_does_what_the_key_does() {
    let (mut a, _rx) = app();
    click_on(&mut a, Target::Action(Action::Settings));
    assert_eq!(a.screen, Screen::Settings);
    let (mut k, _krx) = app();
    press(&mut k, KeyCode::Char('s'));
    assert_eq!(k.screen, Screen::Settings, "the key gives the same screen");

    // In a dialog a hint presses its key.
    let (mut a, _rx) = app();
    a.popup = Some(Popup::Confirm {
        text: "?".into(),
        kind: ConfirmKind::Quit,
    });
    click_on(&mut a, Target::Key(KeyCode::Char('n'), KeyModifiers::NONE));
    assert!(a.popup.is_none(), "n closes the question");
}

#[tokio::test]
async fn the_mode_in_the_status_line_switches_it() {
    let (mut a, mut rx) = app();
    click_on(&mut a, Target::Action(Action::ToggleMode));
    assert_eq!(sent(&mut rx), vec![Cmd::ToggleMode]);
}

#[tokio::test]
async fn the_wheel_turns_the_list_under_the_pointer_not_the_focused_one() {
    let (mut a, _rx) = app();
    for n in 0..60 {
        a.on_link(LinkEvent::Update(Update::Log(LogLine {
            time: "00:00:00".into(),
            level: Level::Info,
            text: format!("line {n}"),
        })));
    }
    draw(100, 30, &mut a);
    assert_eq!(a.focus, Focus::Servers);
    assert_eq!(a.log_scroll, 0);
    let logs = centre(a.hits.find(Target::Panel(Focus::Logs)).unwrap());
    assert_eq!(a.hits.wheel_at(logs.0, logs.1), Some(Wheel::Logs));
    a.handle_mouse(mouse(MouseEventKind::ScrollUp, logs));
    assert!(a.log_scroll > 0, "the logs moved up and follow no more");
    assert_eq!(a.selected, 1, "the focused list did not move");
    // And a wheel on the servers moves the selection.
    let servers = centre(a.hits.find(Target::Panel(Focus::Servers)).unwrap());
    assert_eq!(a.hits.wheel_at(servers.0, servers.1), Some(Wheel::Servers));
    a.handle_mouse(mouse(MouseEventKind::ScrollDown, servers));
    assert_eq!(a.selected, 2);
}

#[tokio::test]
async fn a_click_outside_a_dialog_changes_nothing() {
    let (mut a, mut rx) = app();
    a.popup = Some(Popup::Confirm {
        text: "Quit?".into(),
        kind: ConfirmKind::Quit,
    });
    draw(100, 30, &mut a);
    // Over the server list, which a dialog covers.
    let row = a.hits.find(Target::Row(Rows::Servers, 2));
    assert!(row.is_some(), "the row is drawn under the dialog");
    let at = (12, 4);
    assert_eq!(
        a.hits.target_at(at.0, at.1),
        None,
        "the dialog swallows the click"
    );
    a.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), at));
    assert!(a.popup.is_some(), "the dialog stays");
    assert_eq!(a.selected, 1, "what is under it is not clicked");
    assert!(sent(&mut rx).is_empty());
    // The wheel does not reach the list under it either.
    a.handle_mouse(mouse(MouseEventKind::ScrollDown, at));
    assert_eq!(a.selected, 1);
}

#[tokio::test]
async fn the_buttons_of_a_dialog_work() {
    let (mut a, _rx) = app();
    a.popup = Some(Popup::Error("broken".into()));
    click_on(&mut a, Target::Key(KeyCode::Esc, KeyModifiers::NONE));
    assert!(a.popup.is_none());
    a.popup = Some(Popup::Confirm {
        text: "Quit?".into(),
        kind: ConfirmKind::Quit,
    });
    draw(100, 30, &mut a);
    let yes = a
        .hits
        .find(Target::Key(KeyCode::Char('y'), KeyModifiers::NONE))
        .expect("a yes button");
    a.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), centre(yes)));
    assert!(a.should_quit, "yes quits, as the key y does");
}

#[tokio::test]
async fn a_click_on_a_row_of_a_list_dialog_picks_it() {
    let (mut a, _rx) = app();
    a.popup = Some(Popup::Select {
        title: "Role".into(),
        options: vec!["one".into(), "two".into(), "three".into()],
        selected: 0,
        kind: crate::app::SelectKind::Role(1),
    });
    click_on(&mut a, Target::Pick(Rows::Select, 2));
    assert!(
        a.popup.is_none(),
        "the choice is applied and the dialog closes, as Enter does"
    );
}

#[tokio::test]
async fn the_mouse_off_ignores_every_event() {
    let (mut a, mut rx) = app();
    a.config.ui.mouse = false;
    draw(100, 30, &mut a);
    let at = centre(a.hits.find(Target::Row(Rows::Servers, 2)).unwrap());
    assert!(!a.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), at)));
    assert!(!a.handle_mouse(mouse(MouseEventKind::Moved, at)));
    assert!(!a.handle_mouse(mouse(MouseEventKind::ScrollDown, at)));
    assert_eq!(a.selected, 1);
    assert!(sent(&mut rx).is_empty());
    // The keys of the bar keep their look, nothing is lit.
    assert!(!a
        .hits
        .is_hover(a.hits.find(Target::Row(Rows::Servers, 2)).unwrap()));
}

#[tokio::test]
async fn the_pointer_lights_an_element_and_redraws_only_when_the_element_changes() {
    let (mut a, _rx) = app();
    draw(100, 30, &mut a);
    let first = a.hits.find(Target::Row(Rows::Servers, 1)).unwrap();
    let second = a.hits.find(Target::Row(Rows::Servers, 2)).unwrap();
    assert!(a.handle_mouse(mouse(MouseEventKind::Moved, (first.x + 1, first.y))));
    assert!(
        !a.handle_mouse(mouse(MouseEventKind::Moved, (first.x + 5, first.y))),
        "inside the same row: no new frame"
    );
    assert!(a.hits.is_hover(first));
    assert_eq!(a.selected, 1, "the selection is not changed by the pointer");
    assert!(a.handle_mouse(mouse(MouseEventKind::Moved, (second.x + 1, second.y))));
    assert!(a.hits.is_hover(second) && !a.hits.is_hover(first));
    // Off every element: the light goes out.
    assert!(a.handle_mouse(mouse(MouseEventKind::Moved, (0, 0))));
    assert!(!a.hits.is_hover(second));
}

#[tokio::test]
async fn the_map_is_built_again_for_the_screen_and_the_size() {
    let (mut a, _rx) = app();
    draw(100, 30, &mut a);
    let small = a.hits.find(Target::Panel(Focus::Servers)).unwrap();
    assert!(a.hits.find(Target::Row(Rows::Servers, 2)).is_some());
    draw(140, 40, &mut a);
    let big = a.hits.find(Target::Panel(Focus::Servers)).unwrap();
    assert_ne!(small, big, "a new size, new rectangles");
    a.screen = Screen::Settings;
    draw(100, 30, &mut a);
    assert!(a.hits.find(Target::Row(Rows::Servers, 2)).is_none());
    assert!(a.hits.find(Target::Row(Rows::Settings, 0)).is_some());
}

#[tokio::test]
async fn settings_rows_select_and_a_click_on_the_selected_switch_changes_it() {
    let (mut a, mut rx) = app();
    a.screen = Screen::Settings;
    draw(100, 30, &mut a);
    let index = a
        .settings_rows()
        .iter()
        .position(|r| r.0 == crate::app::SettingId::Mouse)
        .unwrap();
    click_on(&mut a, Target::Row(Rows::Settings, index));
    assert_eq!(a.settings_cursor, index);
    assert!(sent(&mut rx).is_empty(), "the first click only selects");
    click_on(&mut a, Target::Row(Rows::Settings, index));
    assert_eq!(sent(&mut rx), vec![Cmd::Set(Setting::Mouse(false))]);
}

#[tokio::test]
async fn a_rules_row_selects_and_its_check_box_switches_the_rule() {
    let (mut a, mut rx) = app();
    a.screen = Screen::Rules;
    draw(100, 30, &mut a);
    click_on(&mut a, Target::Row(Rows::Rules, 1));
    assert_eq!(a.rules_cursor, 1);
    assert!(sent(&mut rx).is_empty());
    click_on(&mut a, Target::RowAction(Rows::Rules, 1, Action::Toggle));
    let cmds = sent(&mut rx);
    assert_eq!(cmds.len(), 1, "{cmds:?}");

    let (mut k, mut krx) = app();
    k.screen = Screen::Rules;
    k.rules_cursor = 1;
    press(&mut k, KeyCode::Char(' '));
    assert_eq!(sent(&mut krx), cmds, "Space sends the same command");
}
