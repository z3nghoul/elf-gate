use crate::app::{AppState, LinkState, Screen};
use crate::diag::{CheckId, CheckResult, State};
use crate::proto::Cmd;
use tokio::sync::mpsc::unbounded_channel;

fn app(lang: crate::i18n::Lang) -> AppState {
    let (tx, _rx) = unbounded_channel::<Cmd>();
    let mut config = crate::test_support::config_ru();
    config.ui.language = lang;
    let mut a = AppState::with_demo(tx, config);
    a.link = LinkState::Up;
    a.screen = Screen::Diag;
    let rows = [
        (State::Ok, "Xray 26.1.0, /opt/xray/xray", None),
        (
            State::Ok,
            "geoip.dat and geosite.dat are next to the core",
            None,
        ),
        (
            State::Problem,
            "No answer from the server in 5 s.",
            Some("Check the internet."),
        ),
        (State::Skipped, "no Xray core", None),
        (State::Running, "", None),
    ];
    for (id, (state, detail, todo)) in CheckId::ALL.iter().zip(rows) {
        a.diag[CheckId::ALL.iter().position(|i| i == id).unwrap()] = CheckResult {
            id: *id,
            state,
            detail: detail.into(),
            todo: todo.map(Into::into),
            fix: None,
        };
    }
    a.diag_cursor = 2;
    a
}

#[tokio::test]
async fn the_check_screen_in_every_language() {
    for lang in crate::i18n::ALL {
        crate::i18n::with_lang(lang, || {
            let mut a = app(lang);
            let frame = crate::ui::tests_support::draw(100, 30, &mut a);
            snap!(format!("diag_screen_{}", lang.code()), frame);
        });
    }
}

#[tokio::test]
async fn the_check_screen_fits_the_smallest_window() {
    let mut a = app(crate::i18n::Lang::En);
    let frame = crate::ui::tests_support::draw(crate::ui::MIN_WIDTH, crate::ui::MIN_HEIGHT, &mut a);
    assert!(frame.contains(&CheckId::Dns.title()), "{frame}");
}
