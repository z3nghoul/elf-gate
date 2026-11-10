//! System proxy on Linux desktops: GNOME through `gsettings`, KDE through
//! `kwriteconfig5/6` plus a D-Bus notification. Anything else is "not supported"
//! and is never touched.

use crate::platform::{bypass_to_cidr, PlatformError, ProxyAddr, ProxySnapshot, SystemProxy};
use std::collections::BTreeMap;
use std::process::{Command, Stdio};

const GNOME_BACKEND: &str = "gnome";
const KDE_BACKEND: &str = "kde";
/// Stands for "key does not exist" while reading KDE settings.
const KDE_ABSENT: &str = "\u{1}elf-gate-absent\u{1}";

const GNOME_SCHEMA: &str = "org.gnome.system.proxy";
/// (schema, key) pairs we read and write; the snapshot key is `"schema key"`.
const GNOME_KEYS: &[(&str, &str)] = &[
    (GNOME_SCHEMA, "mode"),
    (GNOME_SCHEMA, "ignore-hosts"),
    ("org.gnome.system.proxy.http", "host"),
    ("org.gnome.system.proxy.http", "port"),
    ("org.gnome.system.proxy.https", "host"),
    ("org.gnome.system.proxy.https", "port"),
    ("org.gnome.system.proxy.socks", "host"),
    ("org.gnome.system.proxy.socks", "port"),
];

const KDE_FILE: &str = "kioslaverc";
const KDE_GROUP: &str = "Proxy Settings";
const KDE_KEYS: &[&str] = &[
    "ProxyType",
    "httpProxy",
    "httpsProxy",
    "socksProxy",
    "NoProxyFor",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Desktop {
    Gnome,
    /// Tool names for the installed KDE generation (6 preferred, else 5).
    Kde {
        read: &'static str,
        write: &'static str,
    },
    Other,
}

pub struct Proxy {
    pub desktop: Desktop,
    /// Extra environment for the helper tools (used by tests to stay out of the real session).
    pub env: Vec<(String, String)>,
}

fn tool_exists(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

impl Proxy {
    /// Picks the backend from `XDG_CURRENT_DESKTOP` (e.g. `KDE`, `GNOME`, `ubuntu:GNOME`).
    pub fn detect() -> Self {
        let current = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
        let parts: Vec<String> = current.split(':').map(|p| p.to_ascii_lowercase()).collect();
        let has = |name: &str| parts.iter().any(|p| p == name);
        let desktop = if has("kde") {
            if tool_exists("kwriteconfig6") && tool_exists("kreadconfig6") {
                Desktop::Kde {
                    read: "kreadconfig6",
                    write: "kwriteconfig6",
                }
            } else if tool_exists("kwriteconfig5") && tool_exists("kreadconfig5") {
                Desktop::Kde {
                    read: "kreadconfig5",
                    write: "kwriteconfig5",
                }
            } else {
                Desktop::Other
            }
        } else if has("gnome") && tool_exists("gsettings") {
            Desktop::Gnome
        } else {
            Desktop::Other
        };
        Self {
            desktop,
            env: Vec::new(),
        }
    }

    fn run(&self, program: &str, args: &[&str]) -> Result<String, PlatformError> {
        let out = Command::new(program)
            .args(args)
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .output()
            .map_err(|e| PlatformError::Failed(format!("{program}: {e}")))?;
        if !out.status.success() {
            return Err(PlatformError::Failed(format!(
                "{program} {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    // ---------------- GNOME ----------------

    fn gnome_current(&self) -> Result<ProxySnapshot, PlatformError> {
        let mut values = BTreeMap::new();
        for (schema, key) in GNOME_KEYS {
            values.insert(
                format!("{schema} {key}"),
                self.run("gsettings", &["get", schema, key])?,
            );
        }
        Ok(ProxySnapshot {
            backend: GNOME_BACKEND.into(),
            values,
        })
    }

    fn gnome_set(&self, schema: &str, key: &str, value: &str) -> Result<(), PlatformError> {
        self.run("gsettings", &["set", schema, key, value])
            .map(|_| ())
    }

    fn gnome_enable(&self, addr: &ProxyAddr, bypass: &[String]) -> Result<(), PlatformError> {
        for (schema, port) in [
            ("org.gnome.system.proxy.http", addr.http_port),
            ("org.gnome.system.proxy.https", addr.http_port),
            ("org.gnome.system.proxy.socks", addr.socks_port),
        ] {
            self.gnome_set(schema, "host", &gvariant_string(&addr.host))?;
            self.gnome_set(schema, "port", &port.to_string())?;
        }
        let hosts: Vec<String> = bypass_to_cidr(bypass)
            .iter()
            .map(|h| gvariant_string(h))
            .collect();
        self.gnome_set(
            GNOME_SCHEMA,
            "ignore-hosts",
            &format!("[{}]", hosts.join(", ")),
        )?;
        // The mode goes last, so the desktop never sees a half-configured manual proxy.
        self.gnome_set(GNOME_SCHEMA, "mode", "'manual'")
    }

    fn gnome_restore(&self, previous: &ProxySnapshot) -> Result<(), PlatformError> {
        // Mode first: switch back to the old mode before touching the details.
        let mut keys: Vec<(&str, &str)> = GNOME_KEYS.to_vec();
        keys.sort_by_key(|(_, k)| *k != "mode");
        for (schema, key) in keys {
            if let Some(v) = previous.values.get(&format!("{schema} {key}")) {
                self.gnome_set(schema, key, v)?;
            }
        }
        Ok(())
    }

    // ---------------- KDE ----------------

    fn kde_current(&self, read: &str) -> Result<ProxySnapshot, PlatformError> {
        let mut values = BTreeMap::new();
        for key in KDE_KEYS {
            let v = self.run(
                read,
                &[
                    "--file",
                    KDE_FILE,
                    "--group",
                    KDE_GROUP,
                    "--key",
                    key,
                    "--default",
                    KDE_ABSENT,
                ],
            )?;
            if v != KDE_ABSENT {
                values.insert((*key).to_string(), v);
            }
        }
        Ok(ProxySnapshot {
            backend: KDE_BACKEND.into(),
            values,
        })
    }

    fn kde_write(&self, write: &str, key: &str, value: &str) -> Result<(), PlatformError> {
        self.run(
            write,
            &[
                "--file", KDE_FILE, "--group", KDE_GROUP, "--key", key, value,
            ],
        )
        .map(|_| ())
    }

    fn kde_delete(&self, write: &str, key: &str) -> Result<(), PlatformError> {
        self.run(
            write,
            &[
                "--file", KDE_FILE, "--group", KDE_GROUP, "--key", key, "--delete",
            ],
        )
        .map(|_| ())
    }

    /// Tells running KIO workers (and through them Dolphin, Qt apps, browsers using
    /// KDE settings) to re-read `kioslaverc`. Best effort.
    fn kde_notify(&self) {
        let _ = self.run(
            "dbus-send",
            &[
                "--type=signal",
                "/KIO/Scheduler",
                "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                "string:",
            ],
        );
    }

    fn kde_enable(
        &self,
        write: &str,
        addr: &ProxyAddr,
        bypass: &[String],
    ) -> Result<(), PlatformError> {
        let http = format!("http://{}:{}", addr.host, addr.http_port);
        let socks = format!("socks://{}:{}", addr.host, addr.socks_port);
        self.kde_write(write, "httpProxy", &http)?;
        self.kde_write(write, "httpsProxy", &http)?;
        self.kde_write(write, "socksProxy", &socks)?;
        self.kde_write(write, "NoProxyFor", &bypass_to_cidr(bypass).join(","))?;
        // ProxyType 1 = manual; written last for the same reason as GNOME's mode.
        self.kde_write(write, "ProxyType", "1")?;
        self.kde_notify();
        Ok(())
    }

    fn kde_restore(&self, write: &str, previous: &ProxySnapshot) -> Result<(), PlatformError> {
        for key in KDE_KEYS {
            match previous.values.get(*key) {
                Some(v) => self.kde_write(write, key, v)?,
                None => self.kde_delete(write, key)?,
            }
        }
        self.kde_notify();
        Ok(())
    }
}

/// A string as a GVariant text literal: `'it\'s'`.
fn gvariant_string(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

impl SystemProxy for Proxy {
    fn is_supported(&self) -> bool {
        self.desktop != Desktop::Other
    }

    fn enable(&self, addr: &ProxyAddr, bypass: &[String]) -> Result<(), PlatformError> {
        match self.desktop {
            Desktop::Gnome => self.gnome_enable(addr, bypass),
            Desktop::Kde { write, .. } => self.kde_enable(write, addr, bypass),
            Desktop::Other => Err(PlatformError::Unsupported("desktop environment")),
        }
    }

    fn disable(&self, previous: &ProxySnapshot) -> Result<(), PlatformError> {
        match self.desktop {
            Desktop::Gnome if previous.backend == GNOME_BACKEND => self.gnome_restore(previous),
            Desktop::Kde { write, .. } if previous.backend == KDE_BACKEND => {
                self.kde_restore(write, previous)
            }
            Desktop::Other => Err(PlatformError::Unsupported("desktop environment")),
            _ => Err(PlatformError::Failed(format!(
                "saved settings belong to another desktop ({})",
                previous.backend
            ))),
        }
    }

    fn current(&self) -> Result<ProxySnapshot, PlatformError> {
        match self.desktop {
            Desktop::Gnome => self.gnome_current(),
            Desktop::Kde { read, .. } => self.kde_current(read),
            Desktop::Other => Err(PlatformError::Unsupported("desktop environment")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn gvariant_strings_are_escaped() {
        assert_eq!(gvariant_string("127.0.0.1"), "'127.0.0.1'");
        assert_eq!(gvariant_string("it's"), "'it\\'s'");
    }

    fn addr() -> ProxyAddr {
        ProxyAddr {
            host: "127.0.0.1".into(),
            socks_port: 10808,
            http_port: 10809,
        }
    }

    fn bypass() -> Vec<String> {
        ["localhost", "127.*", "10.*", "192.168.*", "<local>"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("elf-gate-live-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Live test against the real `kwriteconfig`, but with `XDG_CONFIG_HOME` pointing to a
    /// temp dir so the user's own `kioslaverc` is never touched.
    #[test]
    fn kde_roundtrip_in_isolated_config_home() {
        let (read, write) = if tool_exists("kwriteconfig6") && tool_exists("kreadconfig6") {
            ("kreadconfig6", "kwriteconfig6")
        } else if tool_exists("kwriteconfig5") && tool_exists("kreadconfig5") {
            ("kreadconfig5", "kwriteconfig5")
        } else {
            eprintln!("SKIPPED: no kwriteconfig");
            return;
        };
        let home = temp_dir("kde");
        let proxy = Proxy {
            desktop: Desktop::Kde { read, write },
            env: vec![("XDG_CONFIG_HOME".into(), home.display().to_string())],
        };

        // The user already has a manual proxy of their own.
        proxy.kde_write(write, "ProxyType", "1").unwrap();
        proxy
            .kde_write(write, "httpProxy", "http://corp.example:3128")
            .unwrap();
        proxy.kde_write(write, "NoProxyFor", "*.corp").unwrap();
        let before = proxy.current().unwrap();
        assert_eq!(before.values["httpProxy"], "http://corp.example:3128");
        assert!(
            !before.values.contains_key("socksProxy"),
            "absent key must stay absent"
        );

        proxy.enable(&addr(), &bypass()).unwrap();
        let file = std::fs::read_to_string(home.join("kioslaverc")).unwrap();
        assert!(file.contains("httpProxy=http://127.0.0.1:10809"), "{file}");
        assert!(
            file.contains("socksProxy=socks://127.0.0.1:10808"),
            "{file}"
        );
        assert!(
            file.contains("NoProxyFor=localhost,127.0.0.0/8,10.0.0.0/8"),
            "{file}"
        );
        assert!(file.contains("ProxyType=1"), "{file}");

        proxy.disable(&before).unwrap();
        let after = proxy.current().unwrap();
        assert_eq!(after, before, "the user's own proxy must come back exactly");
        let _ = std::fs::remove_dir_all(home);
    }

    /// Same idea for GNOME: the keyfile GSettings backend stores everything under
    /// `XDG_CONFIG_HOME`, so the real dconf database stays untouched.
    #[test]
    fn gnome_roundtrip_with_keyfile_backend() {
        if !tool_exists("gsettings") {
            eprintln!("SKIPPED: no gsettings");
            return;
        }
        let home = temp_dir("gnome");
        let proxy = Proxy {
            desktop: Desktop::Gnome,
            env: vec![
                ("XDG_CONFIG_HOME".into(), home.display().to_string()),
                ("GSETTINGS_BACKEND".into(), "keyfile".into()),
            ],
        };
        if proxy.current().is_err() {
            eprintln!("SKIPPED: GNOME proxy schema or keyfile backend unavailable");
            let _ = std::fs::remove_dir_all(home);
            return;
        }
        proxy.gnome_set(GNOME_SCHEMA, "mode", "'auto'").unwrap();
        proxy
            .gnome_set("org.gnome.system.proxy.http", "host", "'corp.example'")
            .unwrap();
        proxy
            .gnome_set("org.gnome.system.proxy.http", "port", "3128")
            .unwrap();
        let before = proxy.current().unwrap();

        proxy.enable(&addr(), &bypass()).unwrap();
        let during = proxy.current().unwrap();
        assert_eq!(during.values["org.gnome.system.proxy mode"], "'manual'");
        assert_eq!(
            during.values["org.gnome.system.proxy.http host"],
            "'127.0.0.1'"
        );
        assert_eq!(during.values["org.gnome.system.proxy.http port"], "10809");
        assert_eq!(during.values["org.gnome.system.proxy.socks port"], "10808");
        assert!(during.values["org.gnome.system.proxy ignore-hosts"].contains("'10.0.0.0/8'"));

        proxy.disable(&before).unwrap();
        assert_eq!(proxy.current().unwrap(), before);
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn unsupported_desktop_refuses_everything() {
        let proxy = Proxy {
            desktop: Desktop::Other,
            env: Vec::new(),
        };
        assert!(!proxy.is_supported());
        assert!(proxy.enable(&addr(), &[]).is_err());
        assert!(proxy.current().is_err());
    }

    #[test]
    fn snapshot_from_another_desktop_is_not_applied() {
        let proxy = Proxy {
            desktop: Desktop::Gnome,
            env: Vec::new(),
        };
        let foreign = ProxySnapshot {
            backend: KDE_BACKEND.into(),
            values: BTreeMap::new(),
        };
        assert!(proxy.disable(&foreign).is_err());
    }
}
