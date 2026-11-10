//! Interface languages: English (the default), Russian, Ukrainian.
//!
//! The strings live in `locales/{en,ru,uk}.toml` and are embedded in the binary. A key that is
//! missing in a language falls back to English, and a key that is missing everywhere shows as
//! itself: never a panic. Parameters are written `{name}`; plurals use `name.one / few / many /
//! other` (Russian and Ukrainian have the three forms, English has one and other).

use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    En,
    Ru,
    Uk,
}

pub const ALL: [Lang; 3] = [Lang::En, Lang::Ru, Lang::Uk];

impl Lang {
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Ru => "ru",
            Lang::Uk => "uk",
        }
    }

    /// The language's own name, shown as the value of the language setting.
    pub fn native_name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Ru => "\u{420}\u{443}\u{441}\u{441}\u{43a}\u{438}\u{439}",
            Lang::Uk => "\u{423}\u{43a}\u{440}\u{430}\u{457}\u{43d}\u{441}\u{44c}\u{43a}\u{430}",
        }
    }

    pub fn from_code(code: &str) -> Option<Lang> {
        ALL.into_iter()
            .find(|l| l.code() == code.trim().to_ascii_lowercase())
    }

    /// en -> ru -> uk -> en.
    pub fn next(self) -> Lang {
        match self {
            Lang::En => Lang::Ru,
            Lang::Ru => Lang::Uk,
            Lang::Uk => Lang::En,
        }
    }
}

const EN: &str = include_str!("../locales/en.toml");
const RU: &str = include_str!("../locales/ru.toml");
const UK: &str = include_str!("../locales/uk.toml");

type Table = HashMap<String, String>;

fn flatten(prefix: &str, value: &toml::Value, out: &mut Table) {
    match value {
        toml::Value::Table(t) => {
            for (k, v) in t {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(&key, v, out);
            }
        }
        toml::Value::String(s) => {
            out.insert(prefix.to_string(), s.clone());
        }
        _ => {}
    }
}

fn parse(text: &str) -> Table {
    let mut out = Table::new();
    if let Ok(v) = toml::from_str::<toml::Value>(text) {
        flatten("", &v, &mut out);
    }
    out
}

/// All strings of a language, flattened (`area.name`). For the consistency tests.
pub fn table(lang: Lang) -> &'static Table {
    static TABLES: [OnceLock<Table>; 3] = [OnceLock::new(), OnceLock::new(), OnceLock::new()];
    let (idx, text) = match lang {
        Lang::En => (0, EN),
        Lang::Ru => (1, RU),
        Lang::Uk => (2, UK),
    };
    TABLES[idx].get_or_init(|| {
        let mut table = parse(text);
        // A file next to the program overrides single strings: a fix or a new wording needs
        // no rebuild. Unit tests always use the embedded texts.
        if !cfg!(test) {
            if let Some(extra) = external(lang) {
                table.extend(extra);
            }
        }
        table
    })
}

/// `<dir>/<code>.toml`, where `dir` is `$ELF_GATE_LOCALES` or `locales/` beside the executable.
fn external(lang: Lang) -> Option<Table> {
    let dir = std::env::var_os("ELF_GATE_LOCALES")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::current_exe()
                .ok()?
                .parent()
                .map(|p| p.join("locales"))
        })?;
    external_in(&dir, lang)
}

fn external_in(dir: &std::path::Path, lang: Lang) -> Option<Table> {
    let text = std::fs::read_to_string(dir.join(format!("{}.toml", lang.code()))).ok()?;
    Some(parse(&text))
}

fn lookup(lang: Lang, key: &str) -> Option<&'static str> {
    table(lang)
        .get(key)
        .or_else(|| table(Lang::En).get(key))
        .map(String::as_str)
}

// ---- the current language

static GLOBAL: AtomicU8 = AtomicU8::new(0);

thread_local! {
    /// A language for this thread only: tests, and `with_lang` (rendering a message twice).
    static OVERRIDE: Cell<Option<Lang>> = const { Cell::new(None) };
}

fn code_of(l: Lang) -> u8 {
    l as u8
}

fn from_code(c: u8) -> Lang {
    match c {
        1 => Lang::Ru,
        2 => Lang::Uk,
        _ => Lang::En,
    }
}

/// The language texts are produced in now.
pub fn current() -> Lang {
    if let Some(l) = OVERRIDE.with(Cell::get) {
        return l;
    }
    // Unit tests were written against the Russian texts and run threads in parallel: without an
    // explicit choice they get Russian, and a choice only ever concerns its own thread.
    if cfg!(test) {
        return Lang::Ru;
    }
    from_code(GLOBAL.load(Ordering::Relaxed))
}

/// Switches the language (the whole process; in unit tests only the calling thread).
pub fn set(lang: Lang) {
    if cfg!(test) {
        OVERRIDE.with(|o| o.set(Some(lang)));
    } else {
        GLOBAL.store(code_of(lang), Ordering::Relaxed);
    }
}

/// Runs `f` with `lang` as the current language of this thread (the file log is always English).
pub fn with_lang<T>(lang: Lang, f: impl FnOnce() -> T) -> T {
    let before = OVERRIDE.with(|o| o.replace(Some(lang)));
    let out = f();
    OVERRIDE.with(|o| o.set(before));
    out
}

// ---- looking strings up

fn substitute(template: &str, args: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (name, value) in args {
        out = out.replace(&format!("{{{name}}}"), value);
    }
    out
}

/// The text for `key` in `lang` with the parameters filled in.
pub fn tr(lang: Lang, key: &str, args: &[(&str, &str)]) -> String {
    match lookup(lang, key) {
        Some(t) => substitute(t, args),
        None => key.to_string(),
    }
}

/// The plural category of `n`: Russian/Ukrainian one, few, many; English one, other.
pub fn plural_category(lang: Lang, n: u64) -> &'static str {
    match lang {
        Lang::En => {
            if n == 1 {
                "one"
            } else {
                "other"
            }
        }
        Lang::Ru | Lang::Uk => {
            let (m10, m100) = (n % 10, n % 100);
            if m10 == 1 && m100 != 11 {
                "one"
            } else if (2..=4).contains(&m10) && !(12..=14).contains(&m100) {
                "few"
            } else {
                "many"
            }
        }
    }
}

/// `key.<category>` for `n`, with `{count}` and the other parameters filled in.
pub fn trn(lang: Lang, key: &str, n: u64, args: &[(&str, &str)]) -> String {
    let category = plural_category(lang, n);
    let full = format!("{key}.{category}");
    let found = lookup(lang, &full)
        .or_else(|| lookup(lang, &format!("{key}.other")))
        .or_else(|| lookup(Lang::En, &full))
        .or_else(|| lookup(Lang::En, &format!("{key}.other")));
    let count = n.to_string();
    match found {
        Some(t) => {
            let mut all: Vec<(&str, &str)> = vec![("count", count.as_str())];
            all.extend_from_slice(args);
            substitute(t, &all)
        }
        None => key.to_string(),
    }
}

/// `t!("area.key")` or `t!("area.key", name = value, ...)` in the current language.
#[macro_export]
macro_rules! t {
    ($key:expr) => {
        $crate::i18n::tr($crate::i18n::current(), $key, &[])
    };
    ($key:expr, $($name:ident = $value:expr),+ $(,)?) => {
        $crate::i18n::tr(
            $crate::i18n::current(),
            $key,
            &[$((stringify!($name), $value.to_string().as_str())),+],
        )
    };
}

/// `tn!("area.key", n)` / `tn!("area.key", n, name = value)`: a plural form (`{count}` is `n`).
#[macro_export]
macro_rules! tn {
    ($key:expr, $n:expr) => {
        $crate::i18n::trn($crate::i18n::current(), $key, ($n) as u64, &[])
    };
    ($key:expr, $n:expr, $($name:ident = $value:expr),+ $(,)?) => {
        $crate::i18n::trn(
            $crate::i18n::current(),
            $key,
            ($n) as u64,
            &[$((stringify!($name), $value.to_string().as_str())),+],
        )
    };
}

#[cfg(test)]
mod tests;
