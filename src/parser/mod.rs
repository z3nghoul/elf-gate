pub mod vless;

use crate::model::server::Server;
use percent_encoding::percent_decode_str;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("пустая ссылка")]
    Empty,
    #[error("это не ссылка на сервер (ожидается схема://...)")]
    NotALink,
    #[error("неизвестная схема: {0}://")]
    UnknownScheme(String),
    #[error("некорректная ссылка: {0}")]
    InvalidUrl(String),
    #[error("в ссылке нет UUID")]
    MissingUuid,
    #[error("в ссылке нет адреса сервера")]
    MissingHost,
    #[error("в ссылке нет порта")]
    MissingPort,
}

/// Schemes we recognise but do not support yet; they are imported as greyed-out servers.
const UNSUPPORTED_SCHEMES: &[&str] = &[
    "vmess",
    "trojan",
    "ss",
    "ssr",
    "hysteria",
    "hysteria2",
    "hy2",
    "tuic",
    "wireguard",
];

/// Parses a single share link. Never panics, whatever the input.
pub fn parse_link(input: &str) -> Result<Server, ParseError> {
    let link = input.trim();
    if link.is_empty() {
        return Err(ParseError::Empty);
    }
    let (scheme, _) = link.split_once("://").ok_or(ParseError::NotALink)?;
    let scheme = scheme.to_ascii_lowercase();
    match scheme.as_str() {
        "vless" => vless::parse(link),
        s if UNSUPPORTED_SCHEMES.contains(&s) => Ok(unsupported_server(link, s)),
        _ => Err(ParseError::UnknownScheme(scheme)),
    }
}

fn unsupported_server(link: &str, scheme: &str) -> Server {
    let name = fragment_name(link).unwrap_or_else(|| format!("{scheme}-server"));
    Server::unsupported(
        link,
        name,
        format!("протокол {scheme}:// пока не поддерживается"),
    )
}

/// The percent-decoded `#fragment` of a link, if present and non-empty.
pub fn fragment_name(link: &str) -> Option<String> {
    let (_, frag) = link.split_once('#')?;
    let name = percent_decode_str(frag)
        .decode_utf8_lossy()
        .trim()
        .to_string();
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_garbage_are_errors() {
        assert_eq!(parse_link("   "), Err(ParseError::Empty));
        assert_eq!(parse_link("hello world"), Err(ParseError::NotALink));
        assert_eq!(
            parse_link("gopher://x"),
            Err(ParseError::UnknownScheme("gopher".into()))
        );
    }

    #[test]
    fn unsupported_schemes_are_imported_greyed_out() {
        for link in [
            "vmess://eyJhZGQiOiJ4In0=",
            "trojan://pass@host:443#My%20Trojan",
            "ss://YWVzOnB3@host:8388#SS",
            "hysteria2://pw@host:443#HY2",
        ] {
            let s = parse_link(link).unwrap();
            assert!(!s.is_supported(), "{link}");
            assert_eq!(s.link, link);
        }
        assert_eq!(
            parse_link("trojan://pass@host:443#My%20Trojan")
                .unwrap()
                .name,
            "My Trojan"
        );
        assert_eq!(parse_link("vmess://abc").unwrap().name, "vmess-server");
    }

    #[test]
    fn garbage_never_panics() {
        for s in [
            "vless://",
            "vless://@:",
            "vless://[::1",
            "vless://a@b:99999999",
            "vless://\u{0}\u{1}",
            "://",
            "#",
            "vless://u@h:1?%zz=%",
        ] {
            let _ = parse_link(s);
        }
    }
}
