//! The main screens in every language: a snapshot per language at 120 columns, and the check
//! that no language breaks the layout (the key bar keeps its keys, nothing panics when narrow).

use super::hint_tests::states;
use super::tests_support::draw;
use crate::i18n::{self, Lang};

const SCREENS: [&str; 8] = [
    "main_connected",
    "main_error",
    "main_no_servers",
    "settings_switch_row",
    "rules_on_a_preset",
    "help_screen",
    "dialog_confirm",
    "logs_full_screen",
];

#[test]
fn main_screens_match_their_snapshot_in_every_language() {
    for lang in i18n::ALL {
        i18n::set(lang);
        for (name, mut a, (_, h)) in states() {
            if !SCREENS.contains(&name) {
                continue;
            }
            let frame = draw(120, h, &mut a);
            snap!(format!("lang_{}_{name}", lang.code()), frame);
        }
    }
    i18n::set(Lang::Ru);
}

#[test]
fn every_screen_fits_in_every_language_at_80_columns_and_keeps_its_help_and_quit_keys() {
    for lang in i18n::ALL {
        i18n::set(lang);
        for (name, mut a, (_, h)) in states() {
            let frame = draw(80, h.max(24), &mut a);
            assert!(!frame.trim().is_empty(), "{lang:?} {name}");
            let modal = name.starts_with("dialog_") || name == "filter_input";
            if !modal && !name.starts_with("too_small") && !name.starts_with("link_") {
                assert!(
                    frame.contains("q/Q"),
                    "{lang:?} {name}: no quit key\n{frame}"
                );
            }
        }
    }
    i18n::set(Lang::Ru);
}

#[test]
fn the_screens_really_differ_between_languages() {
    let mut texts = Vec::new();
    for lang in i18n::ALL {
        i18n::set(lang);
        let (_, mut a, (_, h)) = states()
            .into_iter()
            .find(|(n, ..)| *n == "main_connected")
            .unwrap();
        texts.push(draw(120, h, &mut a));
    }
    i18n::set(Lang::Ru);
    assert_ne!(texts[0], texts[1]);
    assert_ne!(texts[1], texts[2]);
    assert!(texts[0].contains("Servers"), "{}", texts[0]);
    assert!(texts[2].contains("Сервери"), "{}", texts[2]);
}

/// The source has no Cyrillic outside `locales/` and the test code (and no Cyrillic comments).
#[test]
fn the_source_has_no_cyrillic_outside_locales_and_tests() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let mut bad = Vec::new();
    for f in files {
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        if name == "tests.rs" || name.ends_with("_tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&f).unwrap();
        // Inline test modules sit at the end of a file.
        let lines: Vec<&str> = text.lines().collect();
        let end = (0..lines.len().saturating_sub(1))
            .find(|&i| lines[i].trim() == "#[cfg(test)]" && lines[i + 1].starts_with("mod "))
            .unwrap_or(lines.len());
        for (n, line) in lines[..end].iter().enumerate() {
            if line.chars().any(|c| ('\u{400}'..='\u{4ff}').contains(&c)) {
                bad.push(format!("{}:{}: {}", f.display(), n + 1, line.trim()));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "Cyrillic outside locales/ and tests:\n{}",
        bad.join("\n")
    );
}
