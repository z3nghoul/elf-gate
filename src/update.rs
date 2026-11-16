//! Update notification: asks GitHub for the releases, decides which one is worth telling the
//! user about. Nothing is downloaded or installed; the user gets the version, the release notes
//! and the link to the release page.

use crate::storage::UpdateChannel;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::time::Duration;

pub const RELEASES_API: &str = "https://api.github.com/repos/z3nghoul/elf-gate/releases";
/// Where the user is sent when a release carries no usable link of its own.
pub const RELEASES_PAGE: &str = "https://github.com/z3nghoul/elf-gate/releases";
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// A check at program start is skipped when the last one is younger than this.
pub const MIN_INTERVAL_SECS: i64 = 6 * 3600;
/// While the program runs, a check is repeated once a day.
pub const DAILY_INTERVAL_SECS: i64 = 24 * 3600;
/// Anything bigger than this is not the releases list.
const MAX_BODY: usize = 2 * 1024 * 1024;
/// Release notes are shown in a window: the rest is cut.
const MAX_NOTES_CHARS: usize = 6000;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Ident {
    /// Numbers rank below words (semver 11.4).
    Num(u64),
    Text(String),
}

/// `MAJOR.MINOR.PATCH[-pre.release]`, compared by the semver rules (build metadata is ignored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    core: [u64; 3],
    pre: Vec<Ident>,
}

impl Version {
    /// `1.0.3`, `v1.0.3`, `1.1.0-rc.1`; anything else is `None`.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let text = text.strip_prefix(['v', 'V']).unwrap_or(text);
        let text = text.split_once('+').map_or(text, |(v, _)| v);
        let (core, pre) = match text.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (text, None),
        };
        let mut parts = core.split('.');
        let mut nums = [0u64; 3];
        for n in &mut nums {
            *n = parts.next()?.parse().ok()?;
        }
        if parts.next().is_some() {
            return None;
        }
        let pre = match pre {
            None => Vec::new(),
            Some(p) => p
                .split('.')
                .map(|id| match id {
                    "" => None,
                    _ if id.bytes().all(|b| b.is_ascii_digit()) => id.parse().ok().map(Ident::Num),
                    _ if id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') => {
                        Some(Ident::Text(id.to_string()))
                    }
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()?,
        };
        Some(Self { core: nums, pre })
    }

    pub fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.core
            .cmp(&other.core)
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                // A release is newer than its own pre-releases.
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.core[0], self.core[1], self.core[2])?;
        for (i, id) in self.pre.iter().enumerate() {
            f.write_str(if i == 0 { "-" } else { "." })?;
            match id {
                Ident::Num(n) => write!(f, "{n}")?,
                Ident::Text(t) => f.write_str(t)?,
            }
        }
        Ok(())
    }
}

/// A published release as the interface needs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    /// Without the leading `v`.
    pub version: String,
    /// GitHub's own flag; the channel decision uses it, not the version text.
    pub prerelease: bool,
    /// The description of the release, as the author wrote it.
    pub notes: String,
    pub url: String,
}

/// The fields of GitHub's answer that matter here.
#[derive(Deserialize)]
struct RawRelease {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
}

/// Text from the network is shown in a terminal: control characters (escape sequences) go.
fn clean(text: &str) -> String {
    let text: String = text
        .replace("\r\n", "\n")
        .chars()
        .filter(|c| *c == '\n' || !c.is_control())
        .collect();
    let text = text.trim();
    if text.chars().count() > MAX_NOTES_CHARS {
        let mut cut: String = text.chars().take(MAX_NOTES_CHARS).collect();
        cut.push('…');
        cut
    } else {
        text.to_string()
    }
}

/// Parses the answer of the releases API. Drafts and tags that are not versions are left out.
/// The link must lead to this project's repository; otherwise the general releases page is used.
pub fn parse_releases(json: &str) -> Result<Vec<Release>, String> {
    let raw: Vec<RawRelease> = serde_json::from_str(json).map_err(|e| e.to_string())?;
    Ok(raw
        .into_iter()
        .filter(|r| !r.draft)
        .filter_map(|r| {
            let version = Version::parse(&r.tag_name)?;
            let url = if r.html_url.starts_with("https://github.com/z3nghoul/elf-gate/") {
                clean(&r.html_url)
            } else {
                RELEASES_PAGE.to_string()
            };
            Some(Release {
                version: version.to_string(),
                prerelease: r.prerelease,
                notes: clean(r.body.as_deref().unwrap_or("")),
                url,
            })
        })
        .collect())
}

/// The newest release that is newer than `current`, fits the channel and was not skipped.
/// `skipped` is a version the user asked not to be reminded about.
pub fn newest<'a>(
    releases: &'a [Release],
    current: &str,
    channel: UpdateChannel,
    skipped: Option<&str>,
) -> Option<&'a Release> {
    let current = Version::parse(current)?;
    releases
        .iter()
        .filter(|r| channel == UpdateChannel::Test || !r.prerelease)
        .filter(|r| skipped != Some(r.version.as_str()))
        .filter_map(|r| Some((Version::parse(&r.version)?, r)))
        .filter(|(v, _)| *v > current)
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, r)| r)
}

/// Whether a check is due. `last` and `now` are Unix seconds. At program start the check waits
/// for [`MIN_INTERVAL_SECS`], later for [`DAILY_INTERVAL_SECS`]. A clock that went back counts
/// as "due" (a stored time in the future would otherwise block the check for good).
pub fn due(last: Option<i64>, now: i64, running: bool) -> bool {
    let wait = if running {
        DAILY_INTERVAL_SECS
    } else {
        MIN_INTERVAL_SECS
    };
    last.is_none_or(|t| now < t || now - t >= wait)
}

/// Downloads the releases list. `socks_port`: go through the local proxy of the running core.
pub async fn fetch(socks_port: Option<u16>) -> Result<Vec<Release>, String> {
    let mut builder = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(concat!("elf-gate/", env!("CARGO_PKG_VERSION")));
    builder = match socks_port {
        // The system proxy (maybe elf-gate's own) is never used implicitly.
        None => builder.no_proxy(),
        Some(port) => builder.proxy(
            reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
                .map_err(|e| e.to_string())?,
        ),
    };
    let client = builder.build().map_err(|e| e.to_string())?;
    let resp = client
        .get(RELEASES_API)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let bytes = resp.bytes().await.map_err(|e| e.without_url().to_string())?;
    if bytes.len() > MAX_BODY {
        return Err("answer too big".into());
    }
    parse_releases(&String::from_utf8_lossy(&bytes))
}

#[cfg(test)]
mod tests;
