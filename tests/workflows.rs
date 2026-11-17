//! The CI files are checked like code: they must be valid YAML (a plain value that contains
//! `: ` is a classic way to break one), every action is pinned to a commit with its version in
//! a comment, and the Linux builds run on the oldest image, which fixes the glibc they need.

use std::path::PathBuf;

fn workflows() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
    let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x == "yml" || x == "yaml")
        })
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read_to_string(e.path()).unwrap(),
            )
        })
        .collect();
    out.sort();
    assert!(!out.is_empty(), "no workflows in {}", dir.display());
    out
}

#[test]
fn every_workflow_is_valid_yaml_with_jobs() {
    for (name, text) in workflows() {
        let doc: serde_yaml::Value =
            serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(
            doc.get("jobs").is_some_and(|j| j.is_mapping()),
            "{name}: no jobs"
        );
    }
}

#[test]
fn every_action_is_pinned_to_a_commit_with_its_version_in_a_comment() {
    for (name, text) in workflows() {
        for (n, line) in text.lines().enumerate() {
            let Some(rest) = line
                .trim_start()
                .strip_prefix("- uses:")
                .or_else(|| line.trim_start().strip_prefix("uses:"))
            else {
                continue;
            };
            let (spec, comment) = rest.split_once('#').unwrap_or((rest, ""));
            let (action, sha) = spec.trim().split_once('@').unwrap_or((spec.trim(), ""));
            if action.starts_with("./") {
                continue; // a local action
            }
            assert!(
                sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()),
                "{name}:{}: `{action}` is not pinned to a commit",
                n + 1
            );
            assert!(
                !comment.trim().is_empty(),
                "{name}:{}: `{action}` has no version comment",
                n + 1
            );
        }
    }
}

#[test]
fn linux_builds_run_on_the_oldest_image_not_on_latest() {
    for (name, text) in workflows() {
        let doc: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();
        let jobs = doc.get("jobs").and_then(|j| j.as_mapping()).unwrap();
        for (job, body) in jobs {
            // Only the jobs that build and package (they have a matrix of systems).
            let Some(matrix) = body.get("strategy").and_then(|s| s.get("matrix")) else {
                continue;
            };
            let text = serde_yaml::to_string(matrix).unwrap();
            assert!(
                !text.contains("ubuntu-latest"),
                "{name}: job {job:?} builds on ubuntu-latest, use ubuntu-22.04 (glibc, docs/release.md)"
            );
        }
    }
}

#[test]
fn the_check_would_catch_a_plain_value_with_a_colon_and_a_space() {
    assert!(serde_yaml::from_str::<serde_yaml::Value>("name: Check: the tag\n").is_err());
    assert!(serde_yaml::from_str::<serde_yaml::Value>("name: \"Check: the tag\"\n").is_ok());
}
