pub mod subscription;
pub mod vless;

use crate::model::server::Server;
use percent_encoding::percent_decode_str;

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    NotALink,
    UnknownScheme(String),
    InvalidUrl(String),
    MissingUuid,
    MissingHost,
    MissingPort,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            ParseError::Empty => crate::t!("parse.empty"),
            ParseError::NotALink => crate::t!("parse.not_a_link"),
            ParseError::UnknownScheme(x) => crate::t!("parse.unknown_scheme", scheme = x),
            ParseError::InvalidUrl(x) => crate::t!("parse.invalid_url", error = x),
            ParseError::MissingUuid => crate::t!("parse.no_uuid"),
            ParseError::MissingHost => crate::t!("parse.no_host"),
            ParseError::MissingPort => crate::t!("parse.no_port"),
        };
        f.write_str(&text)
    }
}

impl std::error::Error for ParseError {}

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
    // One entry of a JSON subscription, kept whole (see model::fullconfig).
    if let Some(json) = link.strip_prefix(crate::model::fullconfig::LINK_PREFIX) {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| ParseError::InvalidUrl(e.to_string()))?;
        return crate::model::fullconfig::parse_entry(&value).map_err(ParseError::InvalidUrl);
    }
    let (scheme, _) = link.split_once("://").ok_or(ParseError::NotALink)?;
    let scheme = scheme.to_ascii_lowercase();
    match scheme.as_str() {
        "vless" => vless::parse(link).map(mark_stub),
        s if UNSUPPORTED_SCHEMES.contains(&s) => Ok(unsupported_server(link, s)),
        _ => Err(ParseError::UnknownScheme(scheme)),
    }
}

/// Placeholder rows (zero UUID, address 0.0.0.0, port 0 or 1) are notices, not servers.
fn mark_stub(mut s: Server) -> Server {
    if crate::model::fullconfig::is_stub(&s.address, s.port, &s.uuid) {
        s.unsupported = Some(crate::t!("parse.stub"));
        s.info_only = true;
    }
    s
}

fn unsupported_server(link: &str, scheme: &str) -> Server {
    let name = fragment_name(link).unwrap_or_else(|| format!("{scheme}-server"));
    Server::unsupported(
        link,
        name,
        crate::t!("parse.unsupported_scheme", scheme = scheme),
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
