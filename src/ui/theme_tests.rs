//! The screens in every theme. A snapshot has the text and a map of the styles: each distinct
//! (colours, modifiers) pair gets a letter in the order it first appears, and the legend names it.

use super::theme::ColorMode;
use super::{tests_support, RenderCtx};
use crate::app::{AppState, Screen};
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use tokio::sync::mpsc::unbounded_channel;

pub const THEMES: [(&str, &str, ColorMode); 4] = [
    ("mocha", "mocha", ColorMode::TrueColor),
    ("latte", "latte", ColorMode::TrueColor),
    ("terminal", "terminal", ColorMode::TrueColor),
    ("nocolor", "mocha", ColorMode::NoColor),
];

pub fn styled_frame(text: &str, buf: &Buffer) -> String {
    let mut legend: Vec<(Color, Color, Modifier)> = Vec::new();
    let mut map = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            let c = &buf[(x, y)];
            let key = (c.fg, c.bg, c.modifier);
            let i = legend.iter().position(|k| *k == key).unwrap_or_else(|| {
                legend.push(key);
                legend.len() - 1
            });
            map.push(char::from(b'A' + (i % 26) as u8));
        }
        map.push('\n');
    }
    let legend = legend
        .iter()
        .enumerate()
        .map(|(i, (fg, bg, m))| {
            format!(
                "{} fg={fg:?} bg={bg:?} mod={m:?}",
                char::from(b'A' + (i % 26) as u8)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("{text}\n--- styles\n{map}--- legend\n{legend}\n")
}

fn screens() -> Vec<(&'static str, Screen)> {
    vec![
        ("main", Screen::Main),
        ("settings", Screen::Settings),
        ("rules", Screen::Rules),
        ("help", Screen::Help),
    ]
}

#[tokio::test]
async fn screens_in_every_theme() {
    for (tname, theme, mode) in THEMES {
        for (sname, screen) in screens() {
            for windows in [false, true] {
                // Only these screens depend on the platform.
                let platform = matches!(sname, "rules" | "settings");
                if windows && !platform {
                    continue;
                }
                let (tx, _rx) = unbounded_channel();
                let mut app = AppState::with_demo(tx, crate::test_support::config_ru());
                app.config.ui.theme = theme.into();
                app.screen = screen;
                let ctx = RenderCtx::new(windows, &app.config.ui, mode);
                let (text, buf) = tests_support::draw_buf(100, 30, &mut app, &ctx);
                let suffix = if platform {
                    if windows {
                        "_windows"
                    } else {
                        "_linux"
                    }
                } else {
                    ""
                };
                insta::assert_snapshot!(
                    format!("theme_{sname}_{tname}{suffix}"),
                    styled_frame(&text, &buf)
                );
            }
        }
    }
}

#[tokio::test]
async fn full_screen_is_filled_with_the_theme_background_unless_transparent() {
    let (tx, _rx) = unbounded_channel();
    let mut app = AppState::with_demo(tx, crate::test_support::config_ru());
    let ctx = RenderCtx::new(false, &app.config.ui, ColorMode::TrueColor);
    let (_, buf) = tests_support::draw_buf(100, 30, &mut app, &ctx);
    for y in 0..30 {
        for x in 0..100 {
            assert_ne!(buf[(x, y)].bg, Color::Reset, "({x},{y})");
        }
    }
    app.config.ui.transparent_bg = true;
    let ctx = RenderCtx::new(false, &app.config.ui, ColorMode::TrueColor);
    let (_, buf) = tests_support::draw_buf(100, 30, &mut app, &ctx);
    // Selection may colour a row; the corner is outside every panel highlight.
    assert_eq!(buf[(0, 0)].bg, Color::Reset);
    assert_eq!(buf[(99, 29)].bg, Color::Reset);
}

#[tokio::test]
async fn no_color_draws_nothing_in_colour() {
    let (tx, _rx) = unbounded_channel();
    let mut app = AppState::with_demo(tx, crate::test_support::config_ru());
    let ctx = RenderCtx::new(false, &app.config.ui, ColorMode::NoColor);
    let (_, buf) = tests_support::draw_buf(100, 30, &mut app, &ctx);
    for y in 0..30 {
        for x in 0..100 {
            let c = &buf[(x, y)];
            assert!(
                matches!(c.fg, Color::Reset) && matches!(c.bg, Color::Reset),
                "({x},{y}) {c:?}"
            );
        }
    }
}

#[tokio::test]
async fn subscription_screen_in_every_theme_and_in_privacy_mode() {
    for (tname, theme, mode) in THEMES {
        for privacy in [false, true] {
            if privacy && tname != "mocha" {
                continue;
            }
            let (tx, _rx) = unbounded_channel();
            let mut app = AppState::with_demo(tx, crate::test_support::config_ru());
            app.config.ui.theme = theme.into();
            app.config.ui.privacy_mode = privacy;
            app.config
                .subscriptions
                .push(crate::storage::SubscriptionConfig {
                    name: "Alpha".into(),
                    url: "https://alpha.example/***".into(),
                    user_agent: Some("custom-ua/1.0".into()),
                    ..Default::default()
                });
            app.open_subscription("Alpha");
            let ctx = RenderCtx::new(false, &app.config.ui, mode);
            let (text, buf) = tests_support::draw_buf(100, 30, &mut app, &ctx);
            let p = if privacy { "_privacy" } else { "" };
            insta::assert_snapshot!(
                format!("theme_subscription_{tname}{p}"),
                styled_frame(&text, &buf)
            );
        }
    }
}
