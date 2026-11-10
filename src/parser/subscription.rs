//! Subscription bodies: base64 (standard or URL-safe, with or without padding) with one link
//! per line, or the same list in plain text.

use super::parse_link;
use crate::model::server::Server;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SubscriptionError {
    #[error(
        "подписка в формате JSON не распознана (ожидается массив конфигов Xray или список ссылок)"
    )]
    Json,
    #[error("в подписке нет ни одной ссылки на сервер")]
    Empty,
}

/// Servers parsed from a subscription plus how many lines were skipped as garbage.
#[derive(Debug)]
pub struct Parsed {
    pub servers: Vec<Server>,
    pub skipped: usize,
}

fn decode_base64(body: &str) -> Option<String> {
    // Providers wrap lines and add stray whitespace: strip it all first.
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return None;
    }
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(compact.trim_end_matches('=')) {
            if let Ok(text) = String::from_utf8(bytes) {
                return Some(text);
            }
        }
        if let Ok(bytes) = engine.decode(&compact) {
            if let Ok(text) = String::from_utf8(bytes) {
                return Some(text);
            }
        }
    }
    None
}

fn looks_like_links(text: &str) -> bool {
    text.lines().any(|l| l.trim().contains("://"))
}

/// A JSON subscription: an array of complete Xray configs (or one config).
fn parse_json(text: &str) -> Result<Parsed, SubscriptionError> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| SubscriptionError::Json)?;
    let entries: Vec<serde_json::Value> = match value {
        serde_json::Value::Array(a) => a,
        obj @ serde_json::Value::Object(_) => vec![obj],
        _ => return Err(SubscriptionError::Json),
    };
    let mut servers = Vec::new();
    let mut skipped = 0;
    for e in entries.iter().filter(|e| e.is_object()) {
        match crate::model::fullconfig::parse_entry(e) {
            Ok(s) => servers.push(s),
            Err(_) => skipped += 1,
        }
    }
    if !servers.iter().any(|s| !s.info_only) && servers.is_empty() {
        return Err(SubscriptionError::Empty);
    }
    Ok(Parsed { servers, skipped })
}

pub fn parse_body(body: &str) -> Result<Parsed, SubscriptionError> {
    let trimmed = body.trim_start_matches('\u{feff}').trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return parse_json(trimmed);
    }
    let text = if looks_like_links(trimmed) {
        trimmed.to_string()
    } else {
        match decode_base64(trimmed) {
            Some(t) if t.trim_start().starts_with('{') || t.trim_start().starts_with('[') => {
                return parse_json(t.trim());
            }
            Some(t) => t,
            None => trimmed.to_string(),
        }
    };
    let mut servers = Vec::new();
    let mut skipped = 0;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        match parse_link(line) {
            Ok(server) => servers.push(server),
            Err(_) => skipped += 1,
        }
    }
    if servers.is_empty() {
        return Err(SubscriptionError::Empty);
    }
    Ok(Parsed { servers, skipped })
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443?security=tls#A";
    const B: &str =
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@b.example.com:443?security=tls#B%20two";
    const T: &str = "trojan://pw@t.example.com:443#T";

    fn list() -> String {
        format!("{A}\n{B}\n{T}\n")
    }

    #[test]
    fn plain_list() {
        let p = parse_body(&list()).unwrap();
        assert_eq!(p.servers.len(), 3);
        assert_eq!(p.servers[1].name, "B two");
        assert!(!p.servers[2].is_supported());
    }

    #[test]
    fn base64_in_all_four_flavours() {
        let text = list();
        for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
            let body = engine.encode(text.as_bytes());
            assert_eq!(parse_body(&body).unwrap().servers.len(), 3, "{body}");
        }
    }

    #[test]
    fn wrapped_base64_and_bom_and_crlf() {
        let body = STANDARD.encode(list().replace('\n', "\r\n").as_bytes());
        let wrapped: Vec<String> = body
            .as_bytes()
            .chunks(20)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect();
        let wrapped = format!("\u{feff}{}\n", wrapped.join("\r\n"));
        assert_eq!(parse_body(&wrapped).unwrap().servers.len(), 3);
    }

    #[test]
    fn garbage_lines_are_counted_not_fatal() {
        let p = parse_body(&format!("{A}\nnot a link ://\nftp://x\n{B}")).unwrap();
        assert_eq!(p.servers.len(), 2);
        assert_eq!(p.skipped, 2);
    }

    #[test]
    fn broken_json_is_a_clear_error_plain_or_base64() {
        assert_eq!(
            parse_body("{\"outbounds\": [").unwrap_err(),
            SubscriptionError::Json
        );
        let b = STANDARD.encode("[1, 2");
        assert_eq!(parse_body(&b).unwrap_err(), SubscriptionError::Json);
        assert_eq!(parse_body("[]").unwrap_err(), SubscriptionError::Empty);
    }

    #[test]
    fn nothing_usable_is_an_error() {
        assert_eq!(parse_body("").unwrap_err(), SubscriptionError::Empty);
        assert_eq!(
            parse_body("hello world").unwrap_err(),
            SubscriptionError::Empty
        );
    }
}
