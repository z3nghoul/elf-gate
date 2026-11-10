mod details;
mod help;
mod logs;
mod popup;
mod rules;
mod servers;
mod settings;
mod statusbar;
pub mod theme;

use crate::app::{AppState, Screen};
use ratatui::layout::{Alignment, Constraint, Layout};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use theme::Theme;

pub const MIN_WIDTH: u16 = 80;
pub const MIN_HEIGHT: u16 = 24;

pub fn render(f: &mut Frame, app: &mut AppState) {
    let th = Theme::dark();
    let area = f.area();

    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        let msg = format!(
            "Увеличьте окно (минимум {MIN_WIDTH}x{MIN_HEIGHT}, сейчас {}x{})",
            area.width, area.height
        );
        f.render_widget(
            Paragraph::new(msg)
                .style(th.warn())
                .alignment(Alignment::Center),
            area,
        );
        return;
    }

    let [body, status] = Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(area);

    match app.screen {
        Screen::Main => {
            let [top, bottom] =
                Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .areas(body);
            let [left, right] =
                Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
                    .areas(top);
            servers::render(f, left, app, &th);
            details::render(f, right, app, &th);
            logs::render(f, bottom, app, &th);
        }
        Screen::LogsFull => logs::render(f, body, app, &th),
        Screen::Rules => rules::render(f, body, &th),
        Screen::Settings => settings::render(f, body, &th),
        Screen::Help => help::render(f, body, &th),
    }
    statusbar::render(f, status, app, &th);
    popup::render(f, area, app, &th);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use tokio::sync::mpsc::unbounded_channel;

    fn draw(w: u16, h: u16, app: &mut AppState) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[tokio::test]
    async fn main_screen_renders_all_panels() {
        let (tx, _rx) = unbounded_channel();
        let mut app = AppState::new(tx);
        let out = draw(100, 30, &mut app);
        println!("{out}");
        for needle in [
            "Серверы",
            "Детали",
            "Логи",
            "Отключено",
            "PROXY",
            "DE-1",
            "? помощь",
        ] {
            assert!(out.contains(needle), "missing {needle}");
        }
    }

    #[tokio::test]
    async fn too_small_window_shows_message() {
        let (tx, _rx) = unbounded_channel();
        let mut app = AppState::new(tx);
        let out = draw(70, 20, &mut app);
        assert!(out.contains("Увеличьте окно"));
        assert!(!out.contains("Серверы"));
    }

    #[tokio::test]
    async fn every_screen_renders_at_minimum_size() {
        let (tx, _rx) = unbounded_channel();
        let mut app = AppState::new(tx);
        for s in [
            Screen::Main,
            Screen::Rules,
            Screen::Settings,
            Screen::Help,
            Screen::LogsFull,
        ] {
            app.screen = s;
            draw(MIN_WIDTH, MIN_HEIGHT, &mut app);
        }
    }
}
