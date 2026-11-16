//! Windows Defender Firewall: allow rules for our programs, and removal of the blocking rules
//! Windows itself creates for them when the user presses "Cancel" in its prompt.
//!
//! Only rules named [`RULE_NAME`] are ours to change. Anything else is touched in exactly one
//! case: a rule that blocks one of our programs and that every rule of the same name is also
//! such a block (the API removes by name, so a shared name would take a foreign rule along).

use crate::event::{now_hms, BgEvent, BgTx, Level, LogLine};
use crate::platform::{Firewall, FwAction, FwDirection, FwRule};
use crate::storage::Config;
use std::path::{Path, PathBuf};

pub const RULE_NAME: &str = "elf-gate";
const DIRECTIONS: [FwDirection; 2] = [FwDirection::In, FwDirection::Out];

/// The programs that need rules: the interface and the background part next to this one, and the
/// core as configured. Only files that exist.
pub fn programs_for(config: &Config) -> Vec<PathBuf> {
    let mut programs = Vec::new();
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
    {
        let suffix = std::env::consts::EXE_SUFFIX;
        for name in ["elf-gate", "elf-gated"] {
            programs.push(dir.join(format!("{name}{suffix}")));
        }
    }
    if let Ok(core) = crate::xray::process::resolve_binary(crate::tun::tun_core_setting(config)) {
        programs.push(core);
    }
    programs.retain(|p| p.is_file());
    programs
}

/// The same path in the form Windows compares it by: case-insensitive, one kind of slash.
fn same_path(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.replace('/', "\\").to_lowercase();
    norm(a) == norm(b)
}

fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_lowercase()
}

fn direction_name(d: FwDirection) -> &'static str {
    match d {
        FwDirection::In => "inbound",
        FwDirection::Out => "outbound",
    }
}

/// Brings the rules in line with `programs`. Every step that fails is logged and skipped.
pub fn sync(fw: &dyn Firewall, programs: &[PathBuf], log: &mut dyn FnMut(String)) {
    let rules = match fw.rules() {
        Ok(r) => r,
        Err(e) => return log(format!("firewall: could not read the rules: {e}")),
    };
    for program in programs {
        let path = program.display().to_string();
        for direction in DIRECTIONS {
            let ours = |r: &&FwRule| {
                r.name == RULE_NAME
                    && r.direction == direction
                    && file_name(&r.program) == file_name(&path)
            };
            if rules
                .iter()
                .filter(ours)
                .any(|r| same_path(&r.program, &path) && r.enabled && r.action == FwAction::Allow)
            {
                continue;
            }
            let result = match rules.iter().find(ours) {
                Some(old) if !same_path(&old.program, &path) => {
                    log(format!(
                        "firewall: {} rule for {} moved: {} -> {path}",
                        direction_name(direction),
                        file_name(&path),
                        old.program
                    ));
                    fw.set_program(old, program)
                }
                // Disabled, or not an allow rule: the user's choice, not ours to override.
                Some(_) => continue,
                None => {
                    log(format!(
                        "firewall: allowing {} {path}",
                        direction_name(direction)
                    ));
                    fw.add_allow(RULE_NAME, program, direction)
                }
            };
            if let Err(e) = result {
                log(format!("firewall: rule for {path} not changed: {e}"));
            }
        }
    }
    remove_blocks(fw, &rules, programs, log);
}

fn remove_blocks(
    fw: &dyn Firewall,
    rules: &[FwRule],
    programs: &[PathBuf],
    log: &mut dyn FnMut(String),
) {
    let ours_blocked = |r: &FwRule| {
        r.name != RULE_NAME
            && r.action == FwAction::Block
            && r.enabled
            && programs
                .iter()
                .any(|p| same_path(&r.program, &p.display().to_string()))
    };
    let mut done: Vec<&str> = Vec::new();
    for rule in rules.iter().filter(|r| ours_blocked(r)) {
        if done.contains(&rule.name.as_str()) {
            continue;
        }
        done.push(&rule.name);
        if rules
            .iter()
            .filter(|r| r.name == rule.name)
            .any(|r| !ours_blocked(r))
        {
            log(format!(
                "firewall: blocking rule \"{}\" for {} left alone: its name is shared with other rules",
                rule.name, rule.program
            ));
            continue;
        }
        match fw.remove_by_name(&rule.name) {
            Ok(()) => log(format!(
                "firewall: removed blocking rule \"{}\" ({} {})",
                rule.name,
                direction_name(rule.direction),
                rule.program
            )),
            Err(e) => log(format!(
                "firewall: could not remove blocking rule \"{}\": {e}",
                rule.name
            )),
        }
    }
}

/// The automatic run: nothing without administrator rights, without the setting or without a
/// firewall. Never fails; the log says what happened.
pub fn sync_if_allowed(
    fw: Option<&dyn Firewall>,
    elevated: bool,
    enabled: bool,
    programs: &[PathBuf],
    log: &mut dyn FnMut(String),
) {
    if let (Some(fw), true, true) = (fw, elevated, enabled) {
        sync(fw, programs, log);
    }
}

/// At the start of the background process: runs in the background, reports to the log.
pub fn spawn_auto_sync(config: &Config, tx: &BgTx) {
    if !crate::platform::IS_WINDOWS || !config.tun.manage_firewall {
        return;
    }
    let (programs, tx) = (programs_for(config), tx.clone());
    tokio::task::spawn_blocking(move || {
        let mut log = |text: String| {
            tracing::info!("{text}");
            let _ = tx.send(BgEvent::Log(LogLine {
                time: now_hms(),
                level: Level::Info,
                text,
            }));
        };
        let elevated = crate::platform::privileges().is_elevated();
        let fw = crate::platform::firewall();
        sync_if_allowed(fw.as_deref(), elevated, true, &programs, &mut log);
    });
}

/// `elf-gated --firewall`, started elevated by the user's "configure the firewall" choice:
/// one run, regardless of the automatic setting, then the process ends.
pub fn run_once(config: &Config) -> i32 {
    let Some(fw) = crate::platform::firewall() else {
        return 1;
    };
    if !crate::platform::privileges().is_elevated() {
        tracing::error!("firewall: administrator rights are needed");
        return 1;
    }
    sync(fw.as_ref(), &programs_for(config), &mut |line| {
        tracing::info!("{line}")
    });
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::mock::MockFirewall;

    fn rule(name: &str, program: &str, d: FwDirection, a: FwAction) -> FwRule {
        FwRule {
            name: name.into(),
            program: program.into(),
            direction: d,
            action: a,
            enabled: true,
        }
    }
    fn programs() -> Vec<PathBuf> {
        vec![
            PathBuf::from(r"C:\elf\elf-gate.exe"),
            PathBuf::from(r"C:\elf\elf-gated.exe"),
            PathBuf::from(r"C:\elf\xray.exe"),
        ]
    }
    fn run(fw: &MockFirewall, programs: &[PathBuf]) -> Vec<String> {
        let mut lines = Vec::new();
        sync(fw, programs, &mut |l| lines.push(l));
        lines
    }

    #[test]
    fn creates_an_inbound_and_an_outbound_allow_rule_for_each_program() {
        let fw = MockFirewall::default();
        run(&fw, &programs());
        let rules = fw.rules();
        assert_eq!(rules.len(), 6);
        for p in programs() {
            for d in DIRECTIONS {
                assert!(rules.iter().any(|r| r.name == RULE_NAME
                    && r.program == p.display().to_string()
                    && r.direction == d
                    && r.action == FwAction::Allow
                    && r.enabled));
            }
        }
    }

    #[test]
    fn a_second_run_changes_nothing() {
        let fw = MockFirewall::default();
        run(&fw, &programs());
        let before = fw.calls().len();
        run(&fw, &programs());
        assert_eq!(fw.calls().len(), before);
        assert_eq!(fw.rules().len(), 6);
    }

    #[test]
    fn a_moved_folder_updates_the_path_of_our_rules_only() {
        let foreign = rule(
            "other",
            r"C:\elf\xray.exe",
            FwDirection::Out,
            FwAction::Allow,
        );
        let fw = MockFirewall::with_rules(vec![foreign.clone()]);
        run(&fw, &programs());
        let moved: Vec<PathBuf> = programs()
            .iter()
            .map(|p| PathBuf::from(p.display().to_string().replace(r"C:\elf", r"D:\new")))
            .collect();
        let lines = run(&fw, &moved);
        let rules = fw.rules();
        assert_eq!(rules.len(), 7, "no duplicates: {rules:?}");
        assert!(rules.contains(&foreign), "a foreign rule is not touched");
        let ours: Vec<_> = rules.iter().filter(|r| r.name == RULE_NAME).collect();
        assert!(
            ours.iter().all(|r| r.program.starts_with(r"D:\new")),
            "{ours:?}"
        );
        assert_eq!(lines.iter().filter(|l| l.contains("moved")).count(), 6);
    }

    #[test]
    fn removes_only_blocking_rules_for_our_programs_and_logs_each() {
        let ours_block = rule(
            "xray.exe",
            r"C:\elf\xray.exe",
            FwDirection::In,
            FwAction::Block,
        );
        let ours_block2 = rule(
            "elf-gated.exe",
            r"c:\ELF\elf-gated.exe",
            FwDirection::In,
            FwAction::Block,
        );
        let other_block = rule(
            "game.exe",
            r"C:\game\game.exe",
            FwDirection::In,
            FwAction::Block,
        );
        let other_allow = rule(
            "xray allow",
            r"C:\elf\xray.exe",
            FwDirection::In,
            FwAction::Allow,
        );
        let fw = MockFirewall::with_rules(vec![
            ours_block.clone(),
            ours_block2.clone(),
            other_block.clone(),
            other_allow.clone(),
        ]);
        let lines = run(&fw, &programs());
        let rules = fw.rules();
        assert!(!rules.contains(&ours_block) && !rules.contains(&ours_block2));
        assert!(rules.contains(&other_block) && rules.contains(&other_allow));
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.contains("removed blocking"))
                .count(),
            2
        );
    }

    #[test]
    fn a_blocking_rule_sharing_its_name_with_a_foreign_rule_stays() {
        let block = rule(
            "shared",
            r"C:\elf\xray.exe",
            FwDirection::In,
            FwAction::Block,
        );
        let foreign = rule(
            "shared",
            r"C:\game\game.exe",
            FwDirection::In,
            FwAction::Block,
        );
        let fw = MockFirewall::with_rules(vec![block.clone(), foreign.clone()]);
        let lines = run(&fw, &programs());
        assert!(fw.rules().contains(&block) && fw.rules().contains(&foreign));
        assert!(lines.iter().any(|l| l.contains("left alone")), "{lines:?}");
    }

    #[test]
    fn a_disabled_rule_of_ours_is_not_overridden() {
        let mut off = rule(
            RULE_NAME,
            r"C:\elf\xray.exe",
            FwDirection::In,
            FwAction::Allow,
        );
        off.enabled = false;
        let fw = MockFirewall::with_rules(vec![off.clone()]);
        run(&fw, &programs());
        assert!(fw.rules().contains(&off));
        assert_eq!(
            fw.rules()
                .iter()
                .filter(|r| r.program.ends_with("xray.exe"))
                .count(),
            2
        );
    }

    #[test]
    fn without_administrator_rights_or_the_setting_nothing_happens() {
        let block = rule(
            "xray.exe",
            r"C:\elf\xray.exe",
            FwDirection::In,
            FwAction::Block,
        );
        for (elevated, enabled) in [(false, true), (true, false), (false, false)] {
            let fw = MockFirewall::with_rules(vec![block.clone()]);
            let mut lines = Vec::new();
            sync_if_allowed(Some(&fw), elevated, enabled, &programs(), &mut |l| {
                lines.push(l)
            });
            assert!(fw.calls().is_empty() && lines.is_empty());
            assert_eq!(fw.rules(), vec![block.clone()]);
        }
        let fw = MockFirewall::default();
        sync_if_allowed(Some(&fw), true, true, &programs(), &mut |_| {});
        assert_eq!(fw.rules().len(), 6);
    }
}
