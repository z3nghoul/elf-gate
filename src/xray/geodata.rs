//! Which `geosite:` and `geoip:` sets exist in the `.dat` files next to the core. Xray refuses
//! to start when a rule names a missing set, so rules for missing sets are dropped with a
//! warning and the rest keep working (SPEC, stage 7).

use crate::model::rule::EffectiveRules;
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Geo {
    pub geosite: HashSet<String>,
    pub geoip: HashSet<String>,
}

fn varint(b: &[u8], mut i: usize) -> Option<(u64, usize)> {
    let (mut result, mut shift) = (0u64, 0u32);
    loop {
        let byte = *b.get(i)?;
        i += 1;
        result |= u64::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Some((result, i));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

/// Country codes of a `GeoSiteList` / `GeoIPList`: the top level is `repeated entry = 1`, and
/// every entry starts with `string country_code = 1`. Anything else is skipped; malformed
/// input yields what was read so far.
pub fn parse_codes(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let Some((tag, next)) = varint(bytes, i) else {
            break;
        };
        i = next;
        match tag & 7 {
            2 => {
                let Some((len, next)) = varint(bytes, i) else {
                    break;
                };
                let end = next.saturating_add(len as usize);
                if end > bytes.len() {
                    break;
                }
                if tag >> 3 == 1 {
                    let entry = &bytes[next..end];
                    if let Some((inner_tag, j)) = varint(entry, 0) {
                        if inner_tag == (1 << 3 | 2) {
                            if let Some((n, k)) = varint(entry, j) {
                                if let Some(code) = entry.get(k..k + n as usize) {
                                    out.push(String::from_utf8_lossy(code).into_owned());
                                }
                            }
                        }
                    }
                }
                i = end;
            }
            0 => match varint(bytes, i) {
                Some((_, next)) => i = next,
                None => break,
            },
            _ => break,
        }
    }
    out
}

fn base_code(tag: &str) -> String {
    // "geosite:google@ads" -> GOOGLE; "!cn" style negation is not used by our presets.
    tag.split('@')
        .next()
        .unwrap_or(tag)
        .trim_start_matches('!')
        .to_ascii_uppercase()
}

impl Geo {
    /// Reads `geosite.dat` and `geoip.dat` from `dir`; `None` when they cannot be read
    /// (then nothing is filtered and Xray reports any real problem itself).
    pub fn load(dir: &Path) -> Option<Geo> {
        let read = |name: &str| std::fs::read(dir.join(name)).ok();
        Some(Geo {
            geosite: parse_codes(&read("geosite.dat")?).into_iter().collect(),
            geoip: parse_codes(&read("geoip.dat")?).into_iter().collect(),
        })
    }

    #[cfg(test)]
    pub fn from_codes(geosite: &[&str], geoip: &[&str]) -> Geo {
        Geo {
            geosite: geosite.iter().map(|s| s.to_string()).collect(),
            geoip: geoip.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn has_geosite(&self, name: &str) -> bool {
        self.geosite.contains(&base_code(name))
    }

    pub fn has_geoip(&self, name: &str) -> bool {
        self.geoip.contains(&base_code(name))
    }
}

/// Removes rules that name sets missing from the data files. Returns one warning per dropped set.
pub fn drop_missing(rules: &mut EffectiveRules, geo: &Geo) -> Vec<String> {
    let mut warnings = Vec::new();
    rules.domains.retain(|d| match d.strip_prefix("geosite:") {
        Some(name) if !geo.has_geosite(name) => {
            warnings.push(format!(
                "в geosite.dat нет набора «{name}»: правило пропущено"
            ));
            false
        }
        _ => true,
    });
    let mut keep_ip = |ip: &String| match ip.strip_prefix("geoip:") {
        Some(name) if !geo.has_geoip(name) => {
            warnings.push(format!(
                "в geoip.dat нет набора «{name}»: правило пропущено"
            ));
            false
        }
        _ => true,
    };
    rules.ips.retain(&mut keep_ip);
    rules.always_direct_ips.retain(&mut keep_ip);
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint_bytes(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return out;
            }
            out.push(b | 0x80);
        }
    }

    /// One `GeoSite`-shaped entry: code, plus some payload we must skip.
    fn entry(code: &str, payload_len: usize) -> Vec<u8> {
        let mut body = vec![1 << 3 | 2];
        body.extend(varint_bytes(code.len() as u64));
        body.extend(code.as_bytes());
        body.push(2 << 3 | 2); // another field: a nested message of garbage
        body.extend(varint_bytes(payload_len as u64));
        body.extend(vec![0xAB; payload_len]);
        let mut out = vec![1 << 3 | 2];
        out.extend(varint_bytes(body.len() as u64));
        out.extend(body);
        out
    }

    #[test]
    fn reads_country_codes_and_skips_payloads() {
        let mut data = Vec::new();
        for (code, n) in [("CATEGORY-RU", 300), ("PRIVATE", 5), ("DISCORD", 1)] {
            data.extend(entry(code, n));
        }
        assert_eq!(parse_codes(&data), ["CATEGORY-RU", "PRIVATE", "DISCORD"]);
    }

    #[test]
    fn truncated_or_garbage_input_does_not_panic() {
        let full = entry("RU", 50);
        for cut in 0..full.len() {
            let _ = parse_codes(&full[..cut]);
        }
        let _ = parse_codes(&[0xff; 40]);
        assert!(parse_codes(&[]).is_empty());
    }

    #[test]
    fn real_data_files_are_readable_when_present() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("bin");
        let Some(geo) = Geo::load(&dir) else {
            eprintln!("SKIPPED: no bin/geosite.dat");
            return;
        };
        assert!(geo.has_geosite("category-ru"));
        assert!(geo.has_geosite("discord"));
        assert!(geo.has_geoip("private"));
        assert!(!geo.has_geoip("definitely-not-a-country"));
    }

    #[test]
    fn missing_sets_are_dropped_with_a_warning_and_the_rest_stays() {
        let mut rules = EffectiveRules {
            domains: vec![
                "domain:example.ru".into(),
                "geosite:category-ru".into(),
                "geosite:category-ua".into(),
            ],
            ips: vec!["10.0.0.0/8".into(), "geoip:ru".into(), "geoip:ua".into()],
            always_direct_ips: vec!["geoip:private".into()],
            ..EffectiveRules::default()
        };
        let geo = Geo::from_codes(&["CATEGORY-RU"], &["RU", "PRIVATE"]);
        let warnings = drop_missing(&mut rules, &geo);
        assert_eq!(rules.domains, ["domain:example.ru", "geosite:category-ru"]);
        assert_eq!(rules.ips, ["10.0.0.0/8", "geoip:ru"]);
        assert_eq!(rules.always_direct_ips, ["geoip:private"]);
        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("category-ua") && warnings[1].contains("«ua»"));
    }

    #[test]
    fn attributes_in_tags_do_not_confuse_the_lookup() {
        let geo = Geo::from_codes(&["GOOGLE"], &[]);
        assert!(geo.has_geosite("google@ads"));
        assert!(!geo.has_geosite("yandex@ads"));
    }
}
