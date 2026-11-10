//! Text that comes from outside (names of servers and subscriptions, remarks, provider
//! messages) made safe to draw. Terminals draw emoji wider than the width tables say, so a
//! line with a flag or a pictograph shifts by a cell, breaks the frame and leaves stale
//! characters behind. Such characters are replaced or removed; the original strings (in the
//! config and in the subscription) are never changed.

use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

fn is_regional(c: char) -> bool {
    ('\u{1F1E6}'..='\u{1F1FF}').contains(&c)
}

fn regional_letter(c: char) -> char {
    char::from_u32('A' as u32 + (c as u32 - 0x1F1E6)).unwrap_or('?')
}

/// Pictographs, emoji modifiers and the invisible joiners around them.
fn is_dropped(c: char) -> bool {
    let u = c as u32;
    (c.is_control() && !c.is_whitespace())
        || matches!(u,
            0x200B..=0x200F // zero-width space, joiners, direction marks
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x2069
            | 0xFEFF
            | 0xFE00..=0xFE0F // variation selectors (the emoji one is FE0F)
            | 0x20E3 // keycap
            | 0xE0020..=0xE007F // tag characters of subdivision flags
            | 0x00A9 | 0x00AE | 0x203C | 0x2049 | 0x2122 | 0x2139
            | 0x2194..=0x2199 | 0x21A9..=0x21AA
            | 0x231A..=0x231B | 0x2328 | 0x2388 | 0x23CF | 0x23E9..=0x23F3 | 0x23F8..=0x23FA
            | 0x24C2 | 0x25AA..=0x25AB | 0x25B6 | 0x25C0 | 0x25FB..=0x25FE
            | 0x2600..=0x27BF // symbols and dingbats (the lightning bolt is here)
            | 0x2934..=0x2935 | 0x2B05..=0x2B07 | 0x2B1B..=0x2B1C | 0x2B50 | 0x2B55
            | 0x3030 | 0x303D | 0x3297 | 0x3299
            | 0x1F000..=0x1FAFF | 0x1FC00..=0x1FFFD)
            && !is_regional(c)
}

/// Replaces flags by their country code, removes the other emoji, pictographs, joiners,
/// zero-width and control characters, collapses blanks and trims the ends. The result may be
/// empty: see [`display_name_or`].
pub fn display_name(raw: &str) -> String {
    clean(raw).split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The same cleaning for a line of text (a log line): blanks inside are kept as they are.
pub fn clean(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if is_regional(c) {
            if chars.peek().copied().is_some_and(is_regional) {
                let second = chars.next().expect("peeked");
                out.push(regional_letter(c));
                out.push(regional_letter(second));
                // `DE#5` would run together.
                if chars.peek().is_some_and(|n| !n.is_whitespace()) {
                    out.push(' ');
                }
            }
            // A lone regional indicator means nothing: dropped.
        } else if is_dropped(c) {
            // Removed; neighbours that were separated only by it stay separated by a blank
            // when they were blanks, and are joined otherwise (a joiner inside a word).
        } else if c.is_whitespace() {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

/// [`display_name`], or `fallback()` when nothing is left of the name.
pub fn display_name_or(raw: &str, fallback: impl FnOnce() -> String) -> String {
    let name = display_name(raw);
    if name.is_empty() {
        fallback()
    } else {
        name
    }
}

/// The text cut to `cols` columns by grapheme; an `\u{2026}` marks the cut (the end of the name
/// goes, never the beginning).
pub fn cut(text: &str, cols: usize) -> String {
    if cols == 0 {
        return String::new();
    }
    let total = text.width();
    let limit = if total > cols { cols - 1 } else { cols };
    let mut out = String::new();
    let mut used = 0usize;
    for g in text.graphemes(true) {
        let w = g.width();
        if used + w > limit {
            break;
        }
        out.push_str(g);
        used += w;
    }
    if total > cols {
        out.push('\u{2026}');
    }
    out
}

/// The text padded with blanks to exactly `cols` columns (never cut).
pub fn pad(text: &str, cols: usize) -> String {
    let mut out = text.to_string();
    out.extend(std::iter::repeat_n(' ', cols.saturating_sub(text.width())));
    out
}

/// [`cut`] and [`pad`]: exactly `cols` columns.
pub fn fit(text: &str, cols: usize) -> String {
    pad(&cut(text, cols), cols)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_provider_names_are_cleaned() {
        assert_eq!(
            display_name("\u{1F1E9}\u{1F1EA}\u{26A1}\u{FE0F} #5 LTE \u{2014} \u{423}\u{43d}\u{438}\u{432}\u{435}\u{440}\u{441}\u{430}\u{43b}\u{44c}\u{43d}\u{44b}\u{439}"),
            "DE #5 LTE \u{2014} \u{423}\u{43d}\u{438}\u{432}\u{435}\u{440}\u{441}\u{430}\u{43b}\u{44c}\u{43d}\u{44b}\u{439}"
        );
        assert_eq!(
            display_name("\u{1F1FB}\u{1F1F3}\u{1F51E}\u{1F353} \u{410}\u{432}\u{442}\u{43e} | \u{41e}\u{431}\u{445}\u{43e}\u{434} \u{433}\u{43b}\u{443}\u{448}\u{438}\u{43b}\u{43e}\u{43a} \u{26A1}\u{26A1}\u{26A1}"),
            "VN \u{410}\u{432}\u{442}\u{43e} | \u{41e}\u{431}\u{445}\u{43e}\u{434} \u{433}\u{43b}\u{443}\u{448}\u{438}\u{43b}\u{43e}\u{43a}"
        );
        assert_eq!(
            display_name("\u{2B07}\u{FE0F} \u{41e}\u{431}\u{445}\u{43e}\u{434} \u{433}\u{43b}\u{443}\u{448}\u{438}\u{43b}\u{43e}\u{43a} \u{2B07}\u{FE0F}"),
            "\u{41e}\u{431}\u{445}\u{43e}\u{434} \u{433}\u{43b}\u{443}\u{448}\u{438}\u{43b}\u{43e}\u{43a}"
        );
        assert_eq!(display_name("\u{1F525} EtherVPN"), "EtherVPN");
    }

    #[test]
    fn joiners_zero_width_controls_and_blanks_are_removed() {
        assert_eq!(display_name("a\u{200B}b\u{200D}c"), "abc");
        assert_eq!(display_name("  x \u{7} \t  y  "), "x y");
        assert_eq!(display_name("\u{1F468}\u{200D}\u{1F4BB} dev"), "dev");
        // Plain text, accents and non-Latin scripts stay.
        assert_eq!(
            display_name("Se\u{f1}or \u{6771}\u{4eac} #1"),
            "Se\u{f1}or \u{6771}\u{4eac} #1"
        );
        // A lone regional indicator is dropped, a flag followed by text gets a blank.
        assert_eq!(display_name("\u{1F1E9} x"), "x");
        assert_eq!(display_name("\u{1F1E9}\u{1F1EA}#5"), "DE #5");
    }

    #[test]
    fn an_empty_result_uses_the_fallback() {
        assert_eq!(
            display_name_or("\u{1F525}\u{26A1}\u{FE0F}", || "server 3".into()),
            "server 3"
        );
        assert_eq!(display_name_or("ok", || "server 3".into()), "ok");
    }

    #[test]
    fn fit_cuts_by_grapheme_with_an_ellipsis_and_pads_to_the_column() {
        assert_eq!(fit("abc", 5), "abc  ");
        assert_eq!(fit("abcdefgh", 5), "abcd\u{2026}");
        assert_eq!(fit("abcde", 5), "abcde");
        // A combining accent stays with its letter, a wide character counts two columns.
        assert_eq!(
            fit("e\u{301}e\u{301}e\u{301}x", 3),
            "e\u{301}e\u{301}\u{2026}"
        );
        assert_eq!(fit("\u{6771}\u{4eac}\u{5927}", 4).width(), 4);
        assert_eq!(
            fit("\u{6771}\u{4eac}\u{5927}", 5),
            "\u{6771}\u{4eac}\u{2026}"
        );
        assert_eq!(fit("x", 0), "");
    }
}
