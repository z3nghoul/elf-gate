use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// `name.one` -> `name`; other keys stay.
fn base(key: &str) -> String {
    for suffix in [".one", ".few", ".many", ".other"] {
        if let Some(b) = key.strip_suffix(suffix) {
            return b.to_string();
        }
    }
    key.to_string()
}

fn placeholders(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = text;
    while let Some(i) = rest.find('{') {
        let after = &rest[i + 1..];
        match after.find('}') {
            Some(j)
                if after[..j]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && j > 0 =>
            {
                out.insert(after[..j].to_string());
                rest = &after[j + 1..];
            }
            _ => rest = after,
        }
    }
    out
}

fn bases(lang: Lang) -> BTreeSet<String> {
    table(lang).keys().map(|k| base(k)).collect()
}

#[test]
fn every_english_key_exists_in_russian_and_ukrainian_and_nothing_extra() {
    let en = bases(Lang::En);
    for lang in [Lang::Ru, Lang::Uk] {
        let other = bases(lang);
        let missing: Vec<_> = en.difference(&other).collect();
        let extra: Vec<_> = other.difference(&en).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "{lang:?}: missing {missing:?}, extra {extra:?}"
        );
    }
}

#[test]
fn plural_forms_are_complete_for_each_language() {
    let mut problems = Vec::new();
    for lang in ALL {
        let t = table(lang);
        let plural_bases: BTreeSet<String> = t
            .keys()
            .filter(|k| {
                [".one", ".few", ".many", ".other"]
                    .iter()
                    .any(|s| k.ends_with(s))
            })
            .map(|k| base(k))
            .collect();
        for b in plural_bases {
            let need: &[&str] = if lang == Lang::En {
                &["one", "other"]
            } else {
                &["one", "few", "many"]
            };
            for form in need {
                if !t.contains_key(&format!("{b}.{form}")) {
                    problems.push(format!("{lang:?}: {b}.{form}"));
                }
            }
        }
    }
    assert!(problems.is_empty(), "missing plural forms: {problems:?}");
}

#[test]
fn every_key_has_the_same_placeholders_in_all_languages() {
    // Per base key: the union over its forms (a plural form may leave `{count}` out for "one").
    let mut sets: BTreeMap<(String, Lang), BTreeSet<String>> = BTreeMap::new();
    for lang in ALL {
        for (k, v) in table(lang) {
            sets.entry((base(k), lang))
                .or_default()
                .extend(placeholders(v));
        }
    }
    let mut diffs = Vec::new();
    for key in bases(Lang::En) {
        let en = sets
            .get(&(key.clone(), Lang::En))
            .cloned()
            .unwrap_or_default();
        for lang in [Lang::Ru, Lang::Uk] {
            let other = sets.get(&(key.clone(), lang)).cloned().unwrap_or_default();
            // `count` is supplied by the plural lookup itself.
            let strip = |s: &BTreeSet<String>| {
                s.iter()
                    .filter(|p| *p != "count")
                    .cloned()
                    .collect::<BTreeSet<_>>()
            };
            if strip(&en) != strip(&other) {
                diffs.push(format!("{key}: en {en:?} vs {lang:?} {other:?}"));
            }
        }
    }
    assert!(
        diffs.is_empty(),
        "placeholder differences:\n{}",
        diffs.join("\n")
    );
}

#[test]
fn russian_and_ukrainian_plurals_follow_the_rules() {
    for lang in [Lang::Ru, Lang::Uk] {
        let cat = |n| plural_category(lang, n);
        assert_eq!(cat(1), "one");
        assert_eq!(cat(2), "few");
        assert_eq!(cat(5), "many");
        assert_eq!(cat(11), "many");
        assert_eq!(cat(21), "one");
        assert_eq!(cat(22), "few");
        assert_eq!(cat(0), "many");
        assert_eq!(cat(12), "many");
        assert_eq!(cat(14), "many");
        assert_eq!(cat(111), "many");
        assert_eq!(cat(101), "one");
    }
    assert_eq!(plural_category(Lang::En, 1), "one");
    assert_eq!(plural_category(Lang::En, 0), "other");
    assert_eq!(plural_category(Lang::En, 2), "other");
}

#[test]
fn servers_are_counted_in_every_language() {
    let say = |lang, n| trn(lang, "plural.servers", n, &[]);
    assert_eq!(say(Lang::En, 1), "1 server");
    assert_eq!(say(Lang::En, 5), "5 servers");
    assert_eq!(say(Lang::Ru, 1), "1 сервер");
    assert_eq!(say(Lang::Ru, 2), "2 сервера");
    assert_eq!(say(Lang::Ru, 5), "5 серверов");
    assert_eq!(say(Lang::Ru, 11), "11 серверов");
    assert_eq!(say(Lang::Ru, 21), "21 сервер");
    assert_eq!(say(Lang::Ru, 22), "22 сервера");
    assert_eq!(say(Lang::Uk, 1), "1 сервер");
    assert_eq!(say(Lang::Uk, 2), "2 сервери");
    assert_eq!(say(Lang::Uk, 5), "5 серверів");
    assert_eq!(say(Lang::Uk, 11), "11 серверів");
    assert_eq!(say(Lang::Uk, 21), "21 сервер");
    assert_eq!(say(Lang::Uk, 22), "22 сервери");
}

#[test]
fn a_missing_key_falls_back_to_english_and_then_to_the_key_without_a_panic() {
    assert_eq!(tr(Lang::Uk, "no.such.key", &[]), "no.such.key");
    assert_eq!(trn(Lang::Ru, "no.such.plural", 3, &[]), "no.such.plural");
    // A key that exists only in English is still shown in the other languages.
    assert!(lookup(Lang::En, "plural.servers.other").is_some());
    assert_eq!(
        substitute("{a} and {b}", &[("a", "x"), ("b", "y")]),
        "x and y"
    );
}

#[test]
fn the_language_cycles_and_has_its_own_name() {
    assert_eq!(Lang::En.next(), Lang::Ru);
    assert_eq!(Lang::Ru.next(), Lang::Uk);
    assert_eq!(Lang::Uk.next(), Lang::En);
    assert_eq!(Lang::En.native_name(), "English");
    assert_eq!(Lang::Ru.native_name(), "Русский");
    assert_eq!(Lang::Uk.native_name(), "Українська");
    assert_eq!(Lang::from_code("UK"), Some(Lang::Uk));
    assert_eq!(Lang::from_code("de"), None);
    assert_eq!(
        Lang::default(),
        Lang::En,
        "English unless the user chooses otherwise"
    );
}

#[test]
fn with_lang_applies_only_inside_and_restores() {
    set(Lang::Uk);
    assert_eq!(current(), Lang::Uk);
    let inside = with_lang(Lang::En, current);
    assert_eq!(inside, Lang::En);
    assert_eq!(current(), Lang::Uk);
    set(Lang::Ru);
}

#[test]
fn every_string_is_filled_in_and_the_macro_substitutes() {
    for lang in ALL {
        for (k, v) in table(lang) {
            assert!(!v.trim().is_empty(), "{lang:?} {k} is empty");
        }
    }
    set(Lang::En);
    let s = crate::t!("plural.servers.other", count = 7);
    assert_eq!(s, "7 servers");
    set(Lang::Ru);
}
