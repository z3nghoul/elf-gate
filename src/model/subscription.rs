use super::server::Server;
use serde::{Deserialize, Serialize};

/// What the `subscription-userinfo` header says.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionInfo {
    pub upload: u64,
    pub download: u64,
    /// 0 when the provider does not say.
    pub total: u64,
    /// Unix time; `None` = no expiry given.
    pub expire: Option<i64>,
}

impl SubscriptionInfo {
    pub fn used(&self) -> u64 {
        self.upload + self.download
    }
}

#[derive(Debug, Clone)]
pub struct Subscription {
    pub name: String,
    pub servers: Vec<Server>,
    pub collapsed: bool,
    pub info: Option<SubscriptionInfo>,
    /// Unix time of the last successful update (`None` for manual servers and mock data).
    pub updated: Option<i64>,
    /// The group is backed by a URL in `[[subscriptions]]`.
    pub is_remote: bool,
}

/// Civil date `YYYY-MM-DD` of a unix time (UTC), without a date crate.
pub fn format_date(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `YYYY-MM-DD HH:MM` (UTC).
pub fn format_datetime(unix: i64) -> String {
    let secs = unix.rem_euclid(86_400);
    format!(
        "{} {:02}:{:02}",
        format_date(unix),
        secs / 3600,
        secs / 60 % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(format_date(0), "1970-01-01");
        assert_eq!(format_date(1_893_456_000), "2030-01-01");
        assert_eq!(format_date(1_709_164_800), "2024-02-29");
    }
}
