//! Routing rules, presets and how they combine into what the Xray config needs.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    /// Everything goes through the VPN except what the rules list.
    #[default]
    Exclude,
    /// Only what the rules list goes through the VPN.
    Include,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficMode {
    #[default]
    Proxy,
    Tun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    Domain,
    Ip,
    Geosite,
    Geoip,
    Process,
}

impl RuleKind {
    pub fn label(self) -> String {
        match self {
            RuleKind::Domain => crate::t!("rules.kind_domain"),
            RuleKind::Ip => "ip".to_string(),
            RuleKind::Geosite => "geosite".to_string(),
            RuleKind::Geoip => "geoip".to_string(),
            RuleKind::Process => crate::t!("rules.kind_process"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainMatch {
    /// The domain and its subdomains (`domain:`).
    #[default]
    Suffix,
    Full,
    Keyword,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub kind: RuleKind,
    pub value: String,
    #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
    pub domain_match: Option<DomainMatch>,
    #[serde(default = "yes")]
    pub enabled: bool,
}

impl Rule {
    pub fn new(kind: RuleKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
            domain_match: (kind == RuleKind::Domain).then_some(DomainMatch::Suffix),
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Preset {
    pub id: String,
    pub title: String,
    pub routing: RoutingMode,
    #[serde(default)]
    pub processes_windows: Vec<String>,
    #[serde(default)]
    pub processes_linux: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub geosite: Vec<String>,
    #[serde(default)]
    pub geoip: Vec<String>,
    /// Applies in both routing modes (local network, QUIC block).
    #[serde(default)]
    pub always: bool,
    #[serde(default)]
    pub block_udp443: bool,
    #[serde(default)]
    pub note: String,
}

#[derive(Deserialize)]
struct PresetFile {
    preset: Vec<Preset>,
}

const BUILTIN: &str = include_str!("../../presets.toml");

pub fn builtin_presets() -> Vec<Preset> {
    toml::from_str::<PresetFile>(BUILTIN)
        .expect("presets.toml is embedded and tested")
        .preset
}

/// The preset's title in the current language (the file's own title is the fallback).
pub fn preset_title(p: &Preset) -> String {
    let key = format!("preset.{}.title", p.id);
    match crate::i18n::table(crate::i18n::current())
        .get(&key)
        .or_else(|| crate::i18n::table(crate::i18n::Lang::En).get(&key))
    {
        Some(t) => t.clone(),
        None => p.title.clone(),
    }
}

/// The preset's note in the current language.
pub fn preset_note(p: &Preset) -> String {
    let key = format!("preset.{}.note", p.id);
    match crate::i18n::table(crate::i18n::current())
        .get(&key)
        .or_else(|| crate::i18n::table(crate::i18n::Lang::En).get(&key))
    {
        Some(t) => t.clone(),
        None => p.note.clone(),
    }
}

impl Preset {
    /// Process names for one OS (the file lists both).
    pub fn processes(&self, windows: bool) -> &[String] {
        if windows {
            &self.processes_windows
        } else {
            &self.processes_linux
        }
    }

    /// Is the preset in effect for the chosen routing mode? `include` presets list what goes
    /// through the VPN, `exclude` presets what stays direct; the other kind is shown but inactive.
    pub fn active_in(&self, mode: RoutingMode) -> bool {
        self.always || self.routing == mode
    }
}

/// Everything the config generator needs after rules and presets are merged and filtered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveRules {
    /// Process names (TUN mode only).
    pub processes: Vec<String>,
    /// Xray domain strings: `domain:x`, `full:x`, `keyword:x`, `geosite:x`.
    pub domains: Vec<String>,
    /// IP / CIDR / `geoip:x`.
    pub ips: Vec<String>,
    /// Domains only (no geosite): used to decide DNS routing.
    pub plain_domains: Vec<String>,
    pub block_udp443: bool,
    /// Rules that the ALWAYS-direct presets contribute (geoip:private, ...).
    pub always_direct_ips: Vec<String>,
}

fn push_unique(v: &mut Vec<String>, item: String) {
    if !v.contains(&item) {
        v.push(item);
    }
}

pub fn effective_rules(
    mode: RoutingMode,
    rules: &[Rule],
    enabled_presets: &[String],
    presets: &[Preset],
    windows: bool,
) -> EffectiveRules {
    let mut out = EffectiveRules::default();
    for rule in rules.iter().filter(|r| r.enabled) {
        match rule.kind {
            RuleKind::Process => push_unique(&mut out.processes, rule.value.clone()),
            RuleKind::Domain => {
                let prefix = match rule.domain_match.unwrap_or_default() {
                    DomainMatch::Suffix => "domain",
                    DomainMatch::Full => "full",
                    DomainMatch::Keyword => "keyword",
                };
                push_unique(&mut out.domains, format!("{prefix}:{}", rule.value));
                push_unique(&mut out.plain_domains, rule.value.clone());
            }
            RuleKind::Geosite => push_unique(&mut out.domains, format!("geosite:{}", rule.value)),
            RuleKind::Ip => push_unique(&mut out.ips, rule.value.clone()),
            RuleKind::Geoip => push_unique(&mut out.ips, format!("geoip:{}", rule.value)),
        }
    }
    for preset in presets
        .iter()
        .filter(|p| enabled_presets.contains(&p.id) && p.active_in(mode))
    {
        for name in preset.processes(windows) {
            push_unique(&mut out.processes, name.clone());
        }
        for d in &preset.domains {
            push_unique(&mut out.domains, format!("domain:{d}"));
            push_unique(&mut out.plain_domains, d.clone());
        }
        for g in &preset.geosite {
            push_unique(&mut out.domains, format!("geosite:{g}"));
        }
        for g in &preset.geoip {
            let tag = format!("geoip:{g}");
            if preset.always {
                push_unique(&mut out.always_direct_ips, tag);
            } else {
                push_unique(&mut out.ips, tag);
            }
        }
        out.block_udp443 |= preset.block_udp443;
    }
    out
}

/// Entries for the system proxy's bypass list: plain domains and IPs that the rules send
/// direct. Only in `exclude` mode (in `include` the listed things are the ones that must use the
/// proxy). `geosite`, `keyword:` and odd CIDRs cannot be written as bypass patterns and are left
/// to Xray's own routing. CIDRs are kept only where they map to `a.b.*` wildcards.
pub fn bypass_additions(mode: RoutingMode, rules: &EffectiveRules) -> Vec<String> {
    if mode != RoutingMode::Exclude {
        return Vec::new();
    }
    let mut out = Vec::new();
    for d in &rules.domains {
        match d.split_once(':') {
            Some(("domain", name)) => {
                push_unique(&mut out, name.to_string());
                push_unique(&mut out, format!("*.{name}"));
            }
            Some(("full", name)) => push_unique(&mut out, name.to_string()),
            _ => {}
        }
    }
    for ip in &rules.ips {
        if ip.starts_with("geoip:") {
            continue;
        }
        match ip.split_once('/') {
            None if ip.parse::<std::net::Ipv4Addr>().is_ok() => push_unique(&mut out, ip.clone()),
            Some((addr, prefix)) => {
                let (Ok(v4), Ok(n)) = (addr.parse::<std::net::Ipv4Addr>(), prefix.parse::<u8>())
                else {
                    continue;
                };
                let o = v4.octets();
                match n {
                    8 => push_unique(&mut out, format!("{}.*", o[0])),
                    16 => push_unique(&mut out, format!("{}.{}.*", o[0], o[1])),
                    24 => push_unique(&mut out, format!("{}.{}.{}.*", o[0], o[1], o[2])),
                    _ => {}
                }
            }
            None => {}
        }
    }
    out
}

// ---------------------------------------------------------------- validation

/// Checks a user-typed rule value; the error text is shown in the UI.
pub fn validate(kind: RuleKind, value: &str) -> Result<String, String> {
    let v = value.trim();
    if v.is_empty() {
        return Err(crate::t!("rulecheck.empty"));
    }
    match kind {
        RuleKind::Domain => {
            let d = v.trim_start_matches('.').to_ascii_lowercase();
            let ok = d.len() <= 253
                && d.split('.').all(|l| {
                    !l.is_empty()
                        && l.len() <= 63
                        && !l.starts_with('-')
                        && !l.ends_with('-')
                        && l.chars().all(|c| c.is_alphanumeric() || c == '-')
                })
                && d.contains('.');
            ok.then_some(d).ok_or_else(|| crate::t!("rulecheck.domain"))
        }
        RuleKind::Ip => {
            let (addr, prefix) = match v.split_once('/') {
                Some((a, p)) => (a, Some(p)),
                None => (v, None),
            };
            let ip: IpAddr = addr.parse().map_err(|_| crate::t!("rulecheck.ip"))?;
            if let Some(p) = prefix {
                let max = if ip.is_ipv4() { 32 } else { 128 };
                match p.parse::<u8>() {
                    Ok(n) if n <= max => {}
                    _ => return Err(crate::t!("rulecheck.prefix", max = max)),
                }
            }
            Ok(v.to_string())
        }
        RuleKind::Geosite | RuleKind::Geoip => {
            let ok = v
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '!' || c == '@' || c == '_');
            ok.then(|| v.to_ascii_lowercase())
                .ok_or_else(|| crate::t!("rulecheck.set"))
        }
        RuleKind::Process => {
            let name = v.strip_suffix(".exe").unwrap_or(v);
            let ok = !name.is_empty() && !name.contains(['/', '\\']);
            ok.then(|| name.to_string())
                .ok_or_else(|| crate::t!("rulecheck.process"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_presets_parse_and_have_unique_ids() {
        let presets = builtin_presets();
        for id in [
            "discord-only",
            "games-direct",
            "torrents-direct",
            "ru-direct",
            "ua-direct",
            "local-direct",
            "block-quic",
        ] {
            assert!(presets.iter().any(|p| p.id == id), "{id}");
        }
        let mut ids: Vec<_> = presets.iter().map(|p| p.id.as_str()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), presets.len());
        let discord = presets.iter().find(|p| p.id == "discord-only").unwrap();
        assert_eq!(discord.routing, RoutingMode::Include);
        assert!(discord.processes_linux.contains(&"vesktop".to_string()));
        assert!(discord
            .processes_windows
            .iter()
            .all(|n| !n.ends_with(".exe")));
        let ua = presets.iter().find(|p| p.id == "ua-direct").unwrap();
        assert!(
            ua.geosite.is_empty() && ua.geoip.is_empty() && ua.domains.contains(&"ua".to_string()),
            "the bundled geodata has no ua sets: the preset is a domain list"
        );
        assert!(ua.note.contains("geoip:ua"));
        let quic = presets.iter().find(|p| p.id == "block-quic").unwrap();
        assert!(quic.block_udp443 && quic.note.contains("xtls-rprx-vision"));
    }

    #[test]
    fn include_presets_are_inactive_in_exclude_mode_and_the_reverse() {
        let presets = builtin_presets();
        let by = |id: &str| presets.iter().find(|p| p.id == id).unwrap().clone();
        assert!(by("discord-only").active_in(RoutingMode::Include));
        assert!(!by("discord-only").active_in(RoutingMode::Exclude));
        assert!(by("games-direct").active_in(RoutingMode::Exclude));
        assert!(!by("games-direct").active_in(RoutingMode::Include));
        assert!(by("local-direct").active_in(RoutingMode::Include));
        assert!(by("local-direct").active_in(RoutingMode::Exclude));
    }

    #[test]
    fn effective_rules_merge_rules_and_active_presets_without_duplicates() {
        let presets = builtin_presets();
        let rules = vec![
            Rule::new(RuleKind::Process, "obs"),
            Rule::new(RuleKind::Domain, "discord.com"), // also in the preset
            Rule {
                enabled: false,
                ..Rule::new(RuleKind::Process, "disabled-one")
            },
            Rule::new(RuleKind::Ip, "10.1.0.0/16"),
        ];
        let e = effective_rules(
            RoutingMode::Include,
            &rules,
            &[
                "discord-only".into(),
                "games-direct".into(),
                "local-direct".into(),
            ],
            &presets,
            false,
        );
        assert!(e.processes.contains(&"obs".to_string()));
        assert!(!e.processes.contains(&"disabled-one".to_string()));
        assert!(
            !e.processes.contains(&"steam".to_string()),
            "games-direct is inactive in include mode"
        );
        assert_eq!(
            e.domains
                .iter()
                .filter(|d| *d == "domain:discord.com")
                .count(),
            1
        );
        assert!(e.domains.contains(&"domain:discordapp.net".to_string()));
        assert!(e.ips.contains(&"10.1.0.0/16".to_string()));
        assert_eq!(e.always_direct_ips, vec!["geoip:private".to_string()]);
    }

    #[test]
    fn direct_domains_and_ips_feed_the_system_proxy_bypass_list_in_exclude_mode_only() {
        let rules = vec![
            Rule::new(RuleKind::Domain, "example.com"),
            Rule {
                domain_match: Some(DomainMatch::Full),
                ..Rule::new(RuleKind::Domain, "exact.example.org")
            },
            Rule {
                domain_match: Some(DomainMatch::Keyword),
                ..Rule::new(RuleKind::Domain, "kw")
            },
            Rule::new(RuleKind::Geosite, "category-ru"),
            Rule::new(RuleKind::Ip, "203.0.113.7"),
            Rule::new(RuleKind::Ip, "10.20.0.0/16"),
            Rule::new(RuleKind::Ip, "10.20.30.0/25"),
            Rule::new(RuleKind::Geoip, "ru"),
        ];
        let e = effective_rules(RoutingMode::Exclude, &rules, &[], &[], false);
        assert_eq!(
            bypass_additions(RoutingMode::Exclude, &e),
            [
                "example.com",
                "*.example.com",
                "exact.example.org",
                "203.0.113.7",
                "10.20.*"
            ]
        );
        assert!(
            bypass_additions(RoutingMode::Include, &e).is_empty(),
            "in include mode the listed things must NOT bypass the proxy"
        );
    }

    #[test]
    fn domain_match_kinds_map_to_xray_prefixes() {
        let mk = |m| Rule {
            domain_match: Some(m),
            ..Rule::new(RuleKind::Domain, "x.com")
        };
        let e = effective_rules(
            RoutingMode::Exclude,
            &[
                mk(DomainMatch::Suffix),
                mk(DomainMatch::Full),
                mk(DomainMatch::Keyword),
            ],
            &[],
            &[],
            false,
        );
        assert_eq!(e.domains, ["domain:x.com", "full:x.com", "keyword:x.com"]);
    }

    #[test]
    fn validation_accepts_good_and_rejects_bad_input() {
        assert_eq!(
            validate(RuleKind::Domain, " Example.COM ").unwrap(),
            "example.com"
        );
        assert!(validate(RuleKind::Domain, "localhost").is_err());
        assert!(validate(RuleKind::Domain, "bad domain.com").is_err());
        assert!(validate(RuleKind::Domain, "-x.com").is_err());
        assert!(validate(RuleKind::Ip, "10.0.0.0/8").is_ok());
        assert!(validate(RuleKind::Ip, "2001:db8::/32").is_ok());
        assert!(validate(RuleKind::Ip, "10.0.0.0/33").is_err());
        assert!(validate(RuleKind::Ip, "not-an-ip").is_err());
        assert_eq!(
            validate(RuleKind::Geosite, "Category-RU").unwrap(),
            "category-ru"
        );
        assert!(validate(RuleKind::Geoip, "r u").is_err());
        assert_eq!(
            validate(RuleKind::Process, "Discord.exe").unwrap(),
            "Discord"
        );
        assert!(validate(RuleKind::Process, "/usr/bin/steam").is_err());
        assert!(validate(RuleKind::Process, "").is_err());
    }

    #[test]
    fn rules_roundtrip_through_toml() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct W {
            rules: Vec<Rule>,
        }
        let w = W {
            rules: vec![
                Rule::new(RuleKind::Domain, "example.com"),
                Rule::new(RuleKind::Process, "Discord"),
            ],
        };
        let text = toml::to_string_pretty(&w).unwrap();
        assert!(
            text.contains("kind = \"domain\"") && text.contains("match = \"suffix\""),
            "{text}"
        );
        assert_eq!(toml::from_str::<W>(&text).unwrap(), w);
    }
}
