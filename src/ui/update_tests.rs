//! The update notice on screen: the status line, the `n` window, skipping, the settings rows.

use super::tests_support::draw;
use crate::app::tests::view_with;
use crate::app::{AppState, LinkState, Popup, Screen};
use crate::i18n::Lang;
use crate::proto::{Cmd, Setting};
use crate::storage::UpdateChannel;
use crate::update::Release;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

const REALITY: &str =
    "vless://u@h.example.com:443?security=reality&sni=x.org&pbk=K&sid=ab&fp=chrome#R1";

fn release(notes: &str) -> Release {
    Release {
        version: "1.0.4".into(),
        prerelease: false,
        notes: notes.into(),
        url: "https://github.com/z3nghoul/elf-gate/releases/tag/v1.0.4".into(),
    }
}

fn app(lang: Lang, update: Option<Release>) -> (AppState, UnboundedReceiver<Cmd>) {
    let (tx, rx) = unbounded_channel();
    let mut a = AppState::new(tx);
    let mut view = view_with(&[REALITY]);
    view.config.ui.language = lang;
    view.update = update;
    a.apply_view(view);
    a.link = LinkState::Up;
    (a, rx)
}

fn press(a: &mut AppState, c: char) {
    a.handle_event(crate::event::Event::Key(KeyEvent::new(
        KeyCode::Char(c),
        KeyModifiers::NONE,
    )));
}

fn sent(rx: &mut UnboundedReceiver<Cmd>) -> Vec<Cmd> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

#[tokio::test]
async fn the_status_line_names_the_new_version_in_every_language() {
    for (lang, text) in [
        (Lang::En, "Update 1.0.4 available (n)"),
        (Lang::Ru, "Доступна 1.0.4 (n)"),
        (Lang::Uk, "Доступна 1.0.4 (n)"),
    ] {
        let (mut a, _rx) = app(lang, Some(release("notes")));
        assert!(draw(100, 30, &mut a).contains(text), "{lang:?}");
    }
    let (mut a, _rx) = app(Lang::En, None);
    assert!(!draw(100, 30, &mut a).contains("available"));
}

#[tokio::test]
async fn n_opens_the_window_with_notes_and_link_and_other_keys_close_it() {
    let (mut a, mut rx) = app(Lang::En, Some(release("## 1.0.4\n- fixed a thing")));
    press(&mut a, 'n');
    assert!(matches!(a.popup, Some(Popup::Update(_))));
    let screen = draw(100, 30, &mut a);
    for want in [
        "Version 1.0.4 is available",
        "## 1.0.4",
        "- fixed a thing",
        "https://github.com/z3nghoul/elf-gate/releases/tag/v1.0.4",
        " s do not remind",
    ] {
        assert!(screen.contains(want), "{want:?} is missing:\n{screen}");
    }
    press(&mut a, 'x');
    assert!(a.popup.is_none());
    assert!(
        sent(&mut rx).is_empty(),
        "closing does not skip the version"
    );
}

#[tokio::test]
async fn s_skips_the_version_on_any_layout() {
    // `s` and the Russian and Ukrainian letters on the same key.
    for key in ['s', 'S', '\u{44b}', '\u{456}'] {
        let (mut a, mut rx) = app(Lang::En, Some(release("")));
        press(&mut a, 'n');
        press(&mut a, key);
        assert!(a.popup.is_none());
        assert_eq!(
            sent(&mut rx),
            vec![Cmd::SkipUpdate("1.0.4".into())],
            "{key:?}"
        );
    }
}

#[tokio::test]
async fn n_on_a_cyrillic_layout_works_and_without_an_update_it_does_nothing() {
    let (mut a, _rx) = app(Lang::Ru, Some(release("")));
    press(&mut a, '\u{442}'); // the N key on the Russian layout
    assert!(matches!(a.popup, Some(Popup::Update(_))));
    let (mut a, _rx) = app(Lang::En, None);
    press(&mut a, 'n');
    assert!(a.popup.is_none());
}

#[tokio::test]
async fn long_notes_are_cut_and_the_link_and_the_hint_stay_visible() {
    let notes: Vec<String> = (0..80).map(|i| format!("- change number {i}")).collect();
    let (mut a, _rx) = app(Lang::En, Some(release(&notes.join("\n"))));
    press(&mut a, 'n');
    let screen = draw(100, 30, &mut a);
    assert!(screen.contains("- change number 0"));
    assert!(!screen.contains("- change number 79"));
    assert!(screen.contains("Release page: https://github.com/z3nghoul/elf-gate"));
    assert!(screen.contains(" Esc close"));
}

#[tokio::test]
async fn an_empty_description_is_said_so() {
    let (mut a, _rx) = app(Lang::En, Some(release("")));
    press(&mut a, 'n');
    assert!(draw(100, 30, &mut a).contains("The release has no description."));
}

#[tokio::test]
async fn the_settings_rows_switch_the_check_and_the_channel() {
    let (mut a, mut rx) = app(Lang::En, None);
    a.screen = Screen::Settings;
    let rows = a.settings_rows();
    let at = |label: &str| rows.iter().position(|r| r.1 == label).expect(label);
    let check = at("Check for updates");
    let channel = at("Update channel");
    assert_eq!(rows[check].2, "on");
    assert_eq!(rows[channel].2, "stable");

    a.settings_cursor = check;
    a.handle_event(crate::event::Event::Key(KeyEvent::new(
        KeyCode::Enter,
        KeyModifiers::NONE,
    )));
    a.settings_cursor = channel;
    a.handle_event(crate::event::Event::Key(KeyEvent::new(
        KeyCode::Enter,
        KeyModifiers::NONE,
    )));
    assert_eq!(
        sent(&mut rx),
        vec![
            Cmd::Set(Setting::CheckUpdates(false)),
            Cmd::Set(Setting::UpdateChannel(UpdateChannel::Test)),
        ]
    );
}
