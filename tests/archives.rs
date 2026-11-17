//! What goes into the release archives is decided in `packaging/archive-files.txt`; the
//! packaging steps check the folder they built against it. These tests keep the list, the
//! check script, the workflow and the docs telling the same story.

use std::collections::BTreeSet;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    std::fs::read_to_string(root().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// `(archive, file)` of every line of the list.
fn listed() -> Vec<(String, String)> {
    read("packaging/archive-files.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut parts = l.split_whitespace();
            let (archive, file) = (parts.next().unwrap(), parts.next().unwrap());
            assert!(parts.next().is_none(), "one file per line: `{l}`");
            (archive.to_string(), file.to_string())
        })
        .collect()
}

fn files_of(archive: &str) -> BTreeSet<String> {
    listed()
        .into_iter()
        .filter(|(a, _)| a == archive)
        .map(|(_, f)| f)
        .collect()
}

#[test]
fn the_list_holds_two_archives_without_duplicates_and_with_the_licenses() {
    let all = listed();
    let unique: BTreeSet<_> = all.iter().collect();
    assert_eq!(unique.len(), all.len(), "a file is listed twice");
    let archives: BTreeSet<&str> = all.iter().map(|(a, _)| a.as_str()).collect();
    assert_eq!(
        archives,
        BTreeSet::from(["linux-x86_64", "windows-x86_64"]),
        "only the two release archives"
    );
    for (archive, must) in [
        (
            "linux-x86_64",
            vec!["LICENSE", "LICENSE-Xray", "elf-gate", "elf-gated", "xray"],
        ),
        (
            "windows-x86_64",
            vec![
                "LICENSE",
                "LICENSE-Xray",
                "LICENSE-Wintun",
                "wintun.dll",
                "xray.exe",
            ],
        ),
    ] {
        let files = files_of(archive);
        for f in must {
            assert!(files.contains(f), "{archive}: `{f}` must be in the archive");
        }
    }
    // What the program has built in (or what only helps a reader) is not shipped.
    for archive in ["linux-x86_64", "windows-x86_64"] {
        for f in files_of(archive) {
            assert!(
                !f.contains('/')
                    && f != "README.md"
                    && f != "presets.toml"
                    && !f.starts_with("SHA256SUMS"),
                "{archive}: `{f}` does not belong in the archive"
            );
        }
    }
    assert!(files_of("linux-x86_64").contains("elf-gate-tun.sh"));
    assert!(!files_of("windows-x86_64")
        .iter()
        .any(|f| f.ends_with(".bat")));
}

#[test]
fn the_release_workflow_checks_both_folders_against_the_list_and_copies_nothing_else() {
    let yml = read(".github/workflows/release.yml");
    for archive in ["linux-x86_64", "windows-x86_64"] {
        assert!(
            yml.contains(&format!("check-archive.sh {archive} elf-gate-{archive}"))
                || yml.contains(&format!("check-archive.sh {archive} \"$name\"")),
            "{archive}: no check against the list"
        );
    }
    for gone in [
        "locales",
        "presets.toml",
        "README.md",
        "SHA256SUMS.txt",
        "elf-gate-tun.bat",
    ] {
        // SHA256SUMS of the release itself is another step: only these names are checked.
        assert!(
            !yml.contains(&format!("cp {gone}")) && !yml.contains(&format!("'{gone}'")),
            "release.yml still packs `{gone}`"
        );
    }
    assert!(!yml.contains("ln -s"), "no links in the Linux archive");
}

#[test]
fn the_docs_name_every_file_of_the_list() {
    let doc = read("docs/release.md");
    let section = &doc[doc
        .find("## Состав архивов")
        .expect("a section on the contents")..];
    for (archive, file) in listed() {
        // `.exe` files are written as `name` (`name.exe`) in the table.
        let bare = file.trim_end_matches(".exe");
        assert!(
            section.contains(&format!("`{file}`")) || section.contains(&format!("`{bare}`")),
            "docs/release.md does not mention `{file}` ({archive})"
        );
    }
}

#[test]
fn the_tun_script_finds_the_core_beside_itself() {
    let script = read("packaging/scripts/elf-gate-tun.sh");
    assert!(
        script.contains("SRC_DIR=\"$DIR\""),
        "the core is taken from the archive folder"
    );
    assert!(
        !script.contains("SRC_XRAY=\"$DIR/bin/xray\""),
        "the archive has no bin/"
    );
}

#[cfg(unix)]
mod script {
    use super::*;
    use std::process::Command;

    fn run(archive: &str, folder: &std::path::Path) -> (bool, String) {
        let out = Command::new("bash")
            .arg(root().join("packaging/scripts/check-archive.sh"))
            .arg(archive)
            .arg(folder)
            .output()
            .expect("bash");
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    /// A folder with the listed files, removed when the test ends (also when it fails).
    struct Folder(PathBuf);

    impl std::ops::Deref for Folder {
        type Target = PathBuf;
        fn deref(&self) -> &PathBuf {
            &self.0
        }
    }

    impl Drop for Folder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn folder(tag: &str, archive: &str) -> Folder {
        let dir = std::env::temp_dir().join(format!(
            "elf-gate-test-archives-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for f in files_of(archive) {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        Folder(dir)
    }

    #[test]
    fn the_check_accepts_exactly_the_listed_files_and_rejects_a_stray_or_a_missing_one() {
        for archive in ["linux-x86_64", "windows-x86_64"] {
            let dir = folder(archive, archive);
            let (ok, text) = run(archive, &dir);
            assert!(ok, "{archive}: {text}");

            std::fs::write(dir.join("README.md"), b"x").unwrap();
            let (ok, text) = run(archive, &dir);
            assert!(
                !ok && text.contains("Unexpected files") && text.contains("README.md"),
                "{text}"
            );
            std::fs::remove_file(dir.join("README.md")).unwrap();

            std::fs::create_dir(dir.join("bin")).unwrap();
            let (ok, text) = run(archive, &dir);
            assert!(!ok && text.contains("Unexpected folders"), "{text}");
            std::fs::remove_dir(dir.join("bin")).unwrap();

            std::fs::remove_file(dir.join("LICENSE")).unwrap();
            let (ok, text) = run(archive, &dir);
            assert!(
                !ok && text.contains("Missing files") && text.contains("LICENSE"),
                "{text}"
            );
        }
    }

    #[test]
    fn an_unknown_archive_is_an_error() {
        let dir = folder("unknown", "linux-x86_64");
        let (ok, text) = run("macos", &dir);
        assert!(!ok && text.contains("no files listed"), "{text}");
    }
}
