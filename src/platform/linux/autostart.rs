//! Start at login: an XDG autostart entry, `~/.config/autostart/elf-gate.desktop`.

use crate::platform::{Autostart, PlatformError};
use std::fs;
use std::path::PathBuf;

const FILE: &str = "elf-gate.desktop";

pub struct Entry {
    dir: PathBuf,
}

impl Entry {
    pub fn detect() -> Self {
        // `directories` honours XDG_CONFIG_HOME; `autostart` sits next to the app's own config.
        let base = directories::BaseDirs::new()
            .map(|d| d.config_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        Self::in_dir(base.join("autostart"))
    }

    pub fn in_dir(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn path(&self) -> PathBuf {
        self.dir.join(FILE)
    }
}

/// Quoting rules of the Desktop Entry `Exec` key: arguments with special characters go in
/// double quotes, and `"`, `` ` ``, `$`, `\` inside them are escaped with a backslash.
fn exec_arg(a: &str) -> String {
    let special = a.is_empty() || a.chars().any(|c| " \t\n\"'\\><~|&;$*?#()`".contains(c));
    if !special {
        return a.to_string();
    }
    let mut out = String::from("\"");
    for c in a.chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            out.push('\\');
        }
        if c == '%' {
            out.push('%'); // a literal percent is written twice
        }
        out.push(c);
    }
    out.push('"');
    out
}

fn desktop_file(command: &[String]) -> String {
    let exec = command
        .iter()
        .map(|a| exec_arg(&a.replace('%', "%%")))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "[Desktop Entry]\nType=Application\nName=elf-gate\nComment=VPN client for Xray (background part)\nExec={exec}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
    )
}

impl Autostart for Entry {
    fn is_enabled(&self) -> bool {
        self.path().is_file()
    }

    fn enable(&self, command: &[String]) -> Result<(), PlatformError> {
        if command.is_empty() {
            return Err(PlatformError::Failed(crate::t!("err.autostart_empty")));
        }
        let fail = |e: std::io::Error| PlatformError::Failed(crate::t!("err.autostart", error = e));
        fs::create_dir_all(&self.dir).map_err(fail)?;
        fs::write(self.path(), desktop_file(command)).map_err(fail)
    }

    fn disable(&self) -> Result<(), PlatformError> {
        match fs::remove_file(self.path()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(PlatformError::Failed(crate::t!("err.autostart", error = e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("elf-gate-autostart-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn enable_writes_a_desktop_entry_and_disable_removes_it() {
        let d = dir("roundtrip");
        let e = Entry::in_dir(d.clone());
        assert!(!e.is_enabled());
        e.enable(&["/usr/bin/elf-gate".into(), "--background".into()])
            .unwrap();
        assert!(e.is_enabled());
        let text = fs::read_to_string(d.join("elf-gate.desktop")).unwrap();
        assert!(text.starts_with("[Desktop Entry]\n"));
        assert!(
            text.contains("Exec=/usr/bin/elf-gate --background\n"),
            "{text}"
        );
        assert!(text.contains("Terminal=false"));
        e.disable().unwrap();
        assert!(!e.is_enabled());
        // Disabling twice is fine.
        e.disable().unwrap();
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn paths_with_spaces_and_percent_signs_are_quoted() {
        let text = desktop_file(&["/opt/My Apps/elf-gate".into(), "--name=50%".into()]);
        assert!(
            text.contains("Exec=\"/opt/My Apps/elf-gate\" --name=50%%\n"),
            "{text}"
        );
    }

    #[test]
    fn an_empty_command_is_refused() {
        let e = Entry::in_dir(dir("empty"));
        assert!(e.enable(&[]).is_err());
    }
}
