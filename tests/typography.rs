//! The interface uses the plain hyphen: the long and the middle dashes are not drawn
//! the same by every terminal font. Neither is in the locale files, in the strings of the
//! code, or in what the screens print (the snapshots).

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn files(dir: &Path, extension: &str, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            files(&path, extension, out);
        } else if path.extension().is_some_and(|e| e == extension) {
            out.push(path);
        }
    }
}

fn offenders(paths: &[PathBuf]) -> Vec<String> {
    let mut found = Vec::new();
    for path in paths {
        let text = std::fs::read_to_string(path).unwrap();
        for (n, line) in text.lines().enumerate() {
            if line.contains('\u{2014}') || line.contains('\u{2013}') {
                found.push(format!("{}:{}", path.display(), n + 1));
            }
        }
    }
    found
}

#[test]
fn no_long_or_middle_dash_in_the_locales_the_snapshots_or_the_source_strings() {
    let mut locales = Vec::new();
    files(&root().join("locales"), "toml", &mut locales);
    assert_eq!(locales.len(), 3, "en, ru, uk");
    let mut snapshots = Vec::new();
    files(&root().join("src"), "snap", &mut snapshots);
    assert!(!snapshots.is_empty());
    // The code: escapes in the test data of a provider's name are not interface strings and
    // are written as `\u{2014}`, so a literal dash in a .rs file is an interface string.
    let mut sources = Vec::new();
    files(&root().join("src"), "rs", &mut sources);
    let all: Vec<PathBuf> = locales
        .into_iter()
        .chain(snapshots)
        .chain(sources)
        .collect();
    let bad = offenders(&all);
    assert!(bad.is_empty(), "U+2014 / U+2013 at:\n{}", bad.join("\n"));
}
