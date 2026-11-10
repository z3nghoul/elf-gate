//! The one place that hides secrets. Everything that shows or writes text where a secret could
//! be (the interface in privacy mode, the log file, the tray) goes through here.
//!
//! Two strengths:
//! * [`Mode::Secrets`]: links and URLs (tokens in paths!), user ids, keys. Always applied to
//!   what is written to disk.
//! * [`Mode::Full`]: additionally every IP address and domain name and short hex ids. Applied
//!   to what is drawn while privacy mode is on.
//!
//! Style (the same everywhere): an IPv4 address becomes `*.*.*.*`, an IPv6 one `*:*:*:*`, a
//! domain `***` (the whole name, zone included), a home directory `~`, links and URLs
//! `scheme://***`, ids and keys `***`. Ports are kept: they are not secrets and they make
//! debugging possible.

use crate::model::server::Server;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Secrets,
    Full,
}

/// File extensions that look like a domain's last label but are file names.
const FILE_EXTENSIONS: &[&str] = &[
    "dat", "json", "log", "exe", "dll", "toml", "sh", "bat", "so", "txt", "conf", "desktop",
    "sock", "tmp", "rs", "md", "zip", "gz", "pid", "lock", "ini", "yml", "yaml", "xml", "html",
    "js", "css", "py", "service", "tar", "xz", "bin", "cfg", "go",
];

pub const IPV4_MASK: &str = "*.*.*.*";
pub const IPV6_MASK: &str = "*:*:*:*";

/// Characters that end a word.
fn is_delim(c: char) -> bool {
    c.is_whitespace() || "\"'<>()[]{},;|=&?#".contains(c)
}

/// The scheme of a URL that starts at the beginning of `s` (`https` for `https://x`).
fn url_scheme(s: &str) -> Option<&str> {
    let end = s.find("://")?;
    let scheme = &s[..end];
    (!scheme.is_empty()
        && scheme.chars().next()?.is_ascii_alphabetic()
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c)))
    .then_some(scheme)
}

fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(n, p)| p.len() == *n && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// A long run of base64url characters: a key (Reality public keys are 43 characters).
fn is_key(s: &str) -> bool {
    s.len() >= 32
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && s.chars()
            .any(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
}

/// A hex id (a Reality `shortId`, a hash); it needs a digit so that words are left alone.
fn is_hex_id(s: &str, min: usize) -> bool {
    s.len() >= min
        && s.chars().all(|c| c.is_ascii_hexdigit())
        && s.chars().any(|c| c.is_ascii_digit())
}

/// `name.tld` with a real top-level label: not a version number, not a file name.
fn is_domain(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let tld = labels[labels.len() - 1];
    tld.len() >= 2
        // A real zone is lower case; `streamSettings.sockopt.dialerProxy` is an option name.
        && tld.chars().all(|c| c.is_ascii_lowercase())
        && !FILE_EXTENSIONS.contains(&tld.to_ascii_lowercase().as_str())
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_alphanumeric() || c == '-')
        })
}

/// One piece of a word (no `:` or `/` inside).
fn piece(p: &str, mode: Mode) -> String {
    if p.is_empty() {
        return String::new();
    }
    // A trailing dot or comma belongs to the sentence, not to the name.
    let trimmed = p.trim_end_matches(['.', ',', '!']);
    let tail = &p[trimmed.len()..];
    let t = trimmed;
    let masked: Option<String> = if is_uuid(t) || is_key(t) {
        Some("***".into())
    } else if mode == Mode::Full {
        if t.parse::<Ipv4Addr>().is_ok() {
            Some(IPV4_MASK.into())
        } else if is_hex_id(t, 8) {
            Some("***".into())
        } else if is_domain(t) {
            // The whole name, zone included: even `***.app` says which provider it is.
            Some("***".into())
        } else {
            None
        }
    } else if is_hex_id(t, 16) {
        Some("***".into())
    } else {
        None
    };
    match masked {
        Some(m) => format!("{m}{tail}"),
        None => p.to_string(),
    }
}

/// A word that may hold `scheme:host:port`, `host:port`, `host/path`, an IPv6 address.
fn word(w: &str, mode: Mode) -> String {
    if w.contains(':') && w.parse::<Ipv6Addr>().is_ok() {
        return if mode == Mode::Full {
            IPV6_MASK.into()
        } else {
            w.into()
        };
    }
    // "tcp:198.18.0.1:39044", "full:example.com", "domain:x.y"
    let mut out = String::with_capacity(w.len());
    for (i, part) in w.split(':').enumerate() {
        if i > 0 {
            out.push(':');
        }
        // "host/path": the host part is what could be a secret, the path may carry a token too.
        match part.split_once('/') {
            Some((host, rest)) if !host.is_empty() => {
                out.push_str(&piece(host, mode));
                out.push('/');
                out.push_str(&path_part(rest, mode));
            }
            _ => out.push_str(&piece(part, mode)),
        }
    }
    out
}

/// A path after a host: kept, except pieces that look like tokens.
fn path_part(rest: &str, mode: Mode) -> String {
    rest.split('/')
        .map(|seg| piece(seg, mode))
        .collect::<Vec<_>>()
        .join("/")
}

/// Home directories (`/home/<user>`, `/Users/<user>`, `C:\Users\<user>`, `/root`) become `~`:
/// they carry the account name.
pub fn strip_home(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        // The earliest home-looking prefix in what is left.
        let candidates = ["/home/", "/Users/", "\\Users\\", "/root"];
        let hit = candidates
            .iter()
            .filter_map(|p| rest.find(p).map(|i| (i, *p)))
            .min_by_key(|(i, _)| *i);
        let Some((i, pat)) = hit else {
            out.push_str(rest);
            break;
        };
        let mut start = i;
        // A drive letter in front (`C:`) belongs to the home path.
        if pat.starts_with('\\') || pat == "/Users/" {
            let before = &rest[..i];
            if before.len() >= 2
                && before.as_bytes()[before.len() - 1] == b':'
                && before.as_bytes()[before.len() - 2].is_ascii_alphabetic()
            {
                start = i - 2;
            }
        }
        if pat == "/root" {
            let after = &rest[i + pat.len()..];
            let boundary = after
                .chars()
                .next()
                .is_none_or(|c| c == '/' || !c.is_alphanumeric());
            if !boundary {
                out.push_str(&rest[..i + pat.len()]);
                rest = &rest[i + pat.len()..];
                continue;
            }
            out.push_str(&rest[..start]);
            out.push('~');
            rest = after;
            continue;
        }
        let after = &rest[i + pat.len()..];
        let end = after
            .find(|c: char| {
                c == '/' || c == '\\' || c.is_whitespace() || "\"'<>()[]{},;|".contains(c)
            })
            .unwrap_or(after.len());
        out.push_str(&rest[..start]);
        out.push('~');
        rest = &after[end..];
    }
    out
}

/// Hides what must not show in `text`, line by line (tags, ports and plain words stay).
pub fn text(text: &str, mode: Mode) -> String {
    let home_free;
    let text = if mode == Mode::Full {
        home_free = strip_home(text);
        home_free.as_str()
    } else {
        text
    };
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        let c = rest.chars().next().unwrap();
        if is_delim(c) {
            out.push(c);
            rest = &rest[c.len_utf8()..];
            continue;
        }
        if let Some(scheme) = url_scheme(rest) {
            // A whole link or URL: nothing of it may stay (tokens hide in the path and query).
            let end = rest
                .find(|c: char| c.is_whitespace() || "\"'<>)".contains(c))
                .unwrap_or(rest.len());
            out.push_str(scheme);
            out.push_str("://***");
            rest = &rest[end..];
            continue;
        }
        let end = rest.find(is_delim).unwrap_or(rest.len());
        out.push_str(&word(&rest[..end], mode));
        rest = &rest[end..];
    }
    out
}

/// What goes into files and logs: never a link, a URL, a user id or a key.
pub fn secrets(s: &str) -> String {
    text(s, Mode::Secrets)
}

/// A host name or address for display: `*.*.*.*`, `*:*:*:*` or `***`.
pub fn host(h: &str) -> String {
    if h.is_empty() {
        return String::new();
    }
    if h.parse::<Ipv4Addr>().is_ok() {
        return IPV4_MASK.into();
    }
    if h.parse::<Ipv6Addr>().is_ok() || h.contains(':') {
        return IPV6_MASK.into();
    }
    // A name is hidden whole, zone included.
    "***".into()
}

/// A subscription URL or a share link: only the scheme remains.
pub fn url(u: &str) -> String {
    match url_scheme(u.trim()) {
        Some(s) => format!("{s}://***"),
        None => "***".into(),
    }
}

/// The device id: fixed length, nothing of it.
pub fn hwid(h: &str) -> String {
    "*".repeat(h.chars().count().min(16))
}

/// A path, a host header, a service name: shown only as present.
pub fn opaque(s: &str) -> String {
    if s.is_empty() {
        String::new()
    } else {
        "***".into()
    }
}

/// A copy of the server fit for the screen: no address, ids, keys, SNI or transport names.
/// Names (remarks), ports, transport and security kinds, flow and latency stay.
pub fn server(s: &Server) -> Server {
    let mut r = s.clone();
    r.address = host(&r.address);
    r.uuid.clear();
    r.link.clear();
    r.tls.sni = host(&r.tls.sni);
    r.tls.public_key.clear();
    r.tls.short_id.clear();
    r.tls.spider_x = opaque(&r.tls.spider_x);
    r.params.path = opaque(&r.params.path);
    r.params.host = host(&r.params.host);
    r.params.service_name = opaque(&r.params.service_name);
    r.params.authority = host(&r.params.authority);
    if let Some(f) = &mut r.full {
        f.outbounds.clear();
        f.balancers.clear();
        f.observatory = None;
    }
    // Reasons and notices may quote an address.
    if let Some(u) = &r.unsupported {
        r.unsupported = Some(text(u, Mode::Full));
    }
    r
}

#[cfg(test)]
mod tests;
