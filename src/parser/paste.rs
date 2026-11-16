//! What the clipboard holds, for "paste from the clipboard" in the add dialog: share links,
//! subscription URLs, or base64 of a list of links (the format of a plain subscription body).

use crate::parser::parse_link;
use base64::Engine;

/// More entries than this are not a list of servers somebody copied.
const MAX_ITEMS: usize = 1000;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Found {
    /// Share links that parse, in the order they were found.
    pub servers: Vec<String>,
    /// `http://` and `https://` addresses: subscriptions.
    pub subscriptions: Vec<String>,
}

impl Found {
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty() && self.subscriptions.is_empty()
    }
}

fn is_http_url(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    (lower.starts_with("http://") || lower.starts_with("https://"))
        && url::Url::parse(token).is_ok_and(|u| u.host_str().is_some())
}

fn scan(text: &str) -> Found {
    let mut found = Found::default();
    for token in text.split_whitespace().take(MAX_ITEMS) {
        if is_http_url(token) {
            if !found.subscriptions.iter().any(|s| s == token) {
                found.subscriptions.push(token.to_string());
            }
        } else if parse_link(token).is_ok() && !found.servers.iter().any(|s| s == token) {
            found.servers.push(token.to_string());
        }
    }
    found
}

/// The text of a base64 body, if it is one (standard or URL-safe alphabet, padding or not,
/// line breaks allowed).
fn decode_base64(text: &str) -> Option<String> {
    let compact: String = text.split_whitespace().collect();
    if compact.len() < 8 {
        return None;
    }
    let compact = compact.trim_end_matches('=');
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(compact)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(compact))
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// Finds what can be added in the clipboard text. Never fails: text that holds nothing usable
/// gives an empty [`Found`].
pub fn classify(text: &str) -> Found {
    let found = scan(text);
    if !found.is_empty() {
        return found;
    }
    decode_base64(text).map(|d| scan(&d)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str =
        "vless://11111111-1111-1111-1111-111111111111@one.example.com:443?security=tls#one";
    const B: &str =
        "vless://22222222-2222-2222-2222-222222222222@two.example.com:443?security=tls#two";

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    #[test]
    fn one_link() {
        let f = classify(&format!("  {A}\n"));
        assert_eq!(f.servers, vec![A]);
        assert!(f.subscriptions.is_empty());
    }

    #[test]
    fn several_links_in_lines_and_with_spaces_keep_order_and_drop_repeats() {
        let f = classify(&format!("{A}\n{B}\r\n{A} {B}"));
        assert_eq!(f.servers, vec![A, B]);
    }

    #[test]
    fn other_supported_schemes_are_servers() {
        let f = classify("trojan://pw@host.example.com:443#t");
        assert_eq!(f.servers.len(), 1);
    }

    #[test]
    fn a_subscription_url() {
        let f = classify("https://sub.example.com/path?token=abc\n");
        assert_eq!(
            f.subscriptions,
            vec!["https://sub.example.com/path?token=abc"]
        );
        assert!(f.servers.is_empty());
    }

    #[test]
    fn links_and_a_url_together() {
        let f = classify(&format!("{A} https://sub.example.com/x"));
        assert_eq!((f.servers.len(), f.subscriptions.len()), (1, 1));
    }

    #[test]
    fn base64_list_with_and_without_padding_and_url_safe() {
        let body = format!("{A}\n{B}");
        let std = b64(&body);
        assert_eq!(classify(&std).servers, vec![A, B]);
        assert_eq!(classify(std.trim_end_matches('=')).servers, vec![A, B]);
        let url_safe = base64::engine::general_purpose::URL_SAFE.encode(&body);
        assert_eq!(classify(&url_safe).servers, vec![A, B]);
        // A body wrapped in lines, as some providers send it.
        let wrapped = std
            .as_bytes()
            .chunks(40)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(classify(&wrapped).servers, vec![A, B]);
    }

    #[test]
    fn junk_and_empty_hold_nothing() {
        for text in [
            "",
            "   \n ",
            "hello world, this is not a link",
            "vless://",
            "http://",
            "ftp://example.com/file",
            "SGVsbG8gd29ybGQ=", // base64 of "Hello world"
            "\u{0}\u{1}\u{2}",
        ] {
            assert!(classify(text).is_empty(), "{text:?}");
        }
    }
}
