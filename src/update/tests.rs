use super::*;
use crate::storage::UpdateChannel::{Stable, Test};

const SAMPLE: &str = include_str!("releases_sample.json");

fn v(s: &str) -> Version {
    Version::parse(s).unwrap_or_else(|| panic!("{s} must parse"))
}

fn rel(version: &str, prerelease: bool) -> Release {
    Release {
        version: version.into(),
        prerelease,
        notes: String::new(),
        url: RELEASES_PAGE.into(),
    }
}

#[test]
fn versions_parse_and_print_without_the_prefix() {
    assert_eq!(v("v1.0.3").to_string(), "1.0.3");
    assert_eq!(v("1.1.0-rc.1").to_string(), "1.1.0-rc.1");
    assert_eq!(v("1.0.3+build5").to_string(), "1.0.3");
    for bad in [
        "",
        "1.0",
        "1.0.3.4",
        "a.b.c",
        "1.0.3-",
        "1.0.3-a..b",
        "nightly",
        "1.0.-3",
    ] {
        assert!(Version::parse(bad).is_none(), "{bad:?} is not a version");
    }
}

#[test]
fn versions_compare_by_number_not_by_text() {
    assert!(v("1.0.10") > v("1.0.9"));
    assert!(v("1.10.0") > v("1.9.9"));
    assert!(v("2.0.0") > v("1.99.99"));
    assert_eq!(v("1.0.3"), v("v1.0.3+x"));
}

#[test]
fn a_prerelease_is_older_than_its_release_and_ordered_by_semver() {
    assert!(v("1.0.3-rc.1") < v("1.0.3"));
    assert!(v("1.0.3-rc.1") > v("1.0.2"));
    assert!(v("1.0.3-alpha") < v("1.0.3-alpha.1"));
    assert!(v("1.0.3-alpha.1") < v("1.0.3-alpha.beta"));
    assert!(v("1.0.3-alpha.beta") < v("1.0.3-beta"));
    assert!(v("1.0.3-beta.2") < v("1.0.3-beta.11"));
    assert!(v("1.0.3-rc.1") < v("1.0.3-rc.2"));
    assert!(v("1.0.3-rc.1").is_prerelease() && !v("1.0.3").is_prerelease());
}

#[test]
fn the_sample_answer_is_parsed_and_cleaned() {
    let r = parse_releases(SAMPLE).unwrap();
    let versions: Vec<&str> = r.iter().map(|r| r.version.as_str()).collect();
    // The draft and the "nightly" tag are gone.
    assert_eq!(versions, ["1.1.0-rc.1", "1.0.3", "1.0.2"]);
    assert!(r[0].prerelease && !r[1].prerelease);
    // CRLF becomes LF, the escape character is dropped.
    assert_eq!(r[0].notes, "Candidate.\n\n- new thing[31m red");
    assert_eq!(r[1].notes, "## 1.0.3\n\n- mixed mode\n- autostart with TUN");
    assert_eq!(
        r[1].url,
        "https://github.com/z3nghoul/elf-gate/releases/tag/v1.0.3"
    );
    // A link outside the repository is replaced; a null body is empty.
    assert_eq!(r[2].url, RELEASES_PAGE);
    assert_eq!(r[2].notes, "");
}

#[test]
fn bad_json_and_long_notes_are_handled() {
    assert!(parse_releases("not json").is_err());
    assert!(parse_releases("{}").is_err());
    assert_eq!(parse_releases("[]").unwrap(), Vec::new());
    let long = format!(
        r#"[{{"tag_name":"v9.0.0","body":"{}","html_url":""}}]"#,
        "x".repeat(MAX_NOTES_CHARS + 50)
    );
    let r = parse_releases(&long).unwrap();
    assert_eq!(r[0].notes.chars().count(), MAX_NOTES_CHARS + 1);
    assert!(r[0].notes.ends_with('…'));
}

#[test]
fn the_stable_channel_ignores_prereleases_and_the_test_channel_takes_them() {
    let all = parse_releases(SAMPLE).unwrap();
    let stable = newest(&all, "1.0.2", Stable, None).unwrap();
    assert_eq!(stable.version, "1.0.3");
    let test = newest(&all, "1.0.2", Test, None).unwrap();
    assert_eq!(test.version, "1.1.0-rc.1");
    // Nothing is newer than the newest stable release on the stable channel.
    assert!(newest(&all, "1.0.3", Stable, None).is_none());
}

#[test]
fn only_a_newer_version_is_offered() {
    let all = [rel("1.0.3", false), rel("1.0.2", false)];
    assert!(newest(&all, "1.0.3", Stable, None).is_none());
    assert!(newest(&all, "1.0.4", Stable, None).is_none());
    // A pre-release of the version in use is older than it.
    let pre = [rel("1.0.3-rc.1", true)];
    assert!(newest(&pre, "1.0.3", Test, None).is_none());
    // The running pre-release is offered its own release.
    assert_eq!(
        newest(&all, "1.0.3-rc.1", Stable, None).unwrap().version,
        "1.0.3"
    );
    // A current version that is not a version offers nothing.
    assert!(newest(&all, "dev", Stable, None).is_none());
}

#[test]
fn the_newest_wins_whatever_the_order_of_the_list() {
    let all = [
        rel("1.0.4", false),
        rel("1.0.10", false),
        rel("1.0.9", false),
    ];
    assert_eq!(
        newest(&all, "1.0.0", Stable, None).unwrap().version,
        "1.0.10"
    );
}

#[test]
fn a_skipped_version_is_not_offered_but_a_newer_one_is() {
    let all = [rel("1.0.5", false), rel("1.0.4", false)];
    // The newest is skipped: the older (still newer than current) is offered.
    assert_eq!(
        newest(&all, "1.0.3", Stable, Some("1.0.5"))
            .unwrap()
            .version,
        "1.0.4"
    );
    // Only version is skipped: nothing.
    let one = [rel("1.0.4", false)];
    assert!(newest(&one, "1.0.3", Stable, Some("1.0.4")).is_none());
    // A newer release than the skipped one brings the reminder back.
    let newer = [rel("1.0.5", false), rel("1.0.4", false)];
    assert_eq!(
        newest(&newer, "1.0.3", Stable, Some("1.0.4"))
            .unwrap()
            .version,
        "1.0.5"
    );
}

#[test]
fn the_check_interval_is_six_hours_at_start_and_a_day_while_running() {
    let now = 1_800_000_000;
    assert!(due(None, now, false));
    assert!(due(None, now, true));
    // At start: not before 6 hours.
    assert!(!due(Some(now - MIN_INTERVAL_SECS + 1), now, false));
    assert!(due(Some(now - MIN_INTERVAL_SECS), now, false));
    // While running: once a day.
    assert!(!due(Some(now - DAILY_INTERVAL_SECS + 1), now, true));
    assert!(due(Some(now - DAILY_INTERVAL_SECS), now, true));
    // A time stored in the future does not block the check.
    assert!(due(Some(now + 10), now, true));
}
