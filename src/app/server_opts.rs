//! Per-server options kept in `[[overrides]]`: role (primary / backup) and ClientHello
//! fragmentation.

use super::*;
use crate::model::server::ServerRole;

impl AppState {
    /// `(group, override key)` of a server.
    fn server_key_of(&self, id: u64) -> Option<(String, String)> {
        self.subs.iter().find_map(|sub| {
            sub.servers
                .iter()
                .find(|s| s.id == id)
                .map(|s| (sub.name.clone(), override_key(&sub.name, s)))
        })
    }

    /// The server that backs `primary_id` up, if `primary_id` is the primary.
    pub(super) fn backup_for(&self, primary_id: u64) -> Option<Server> {
        let primary = self.server_by_id(primary_id)?;
        if primary.role != Some(ServerRole::Primary) {
            return None;
        }
        self.subs
            .iter()
            .flat_map(|s| s.servers.iter())
            .find(|s| s.role == Some(ServerRole::Backup) && s.is_supported() && s.id != primary_id)
            .cloned()
    }

    pub(super) fn open_role_menu(&mut self) {
        let Some(server) = self.selected_server() else {
            self.status = Some("Выберите сервер (не группу)".into());
            return;
        };
        if !server.is_supported() {
            self.status = Some("Роль можно назначить только поддерживаемому серверу".into());
            return;
        }
        let selected = match server.role {
            None => 0,
            Some(ServerRole::Primary) => 1,
            Some(ServerRole::Backup) => 2,
        };
        self.popup = Some(Popup::Select {
            title: format!("Роль сервера: {}", server.name),
            options: vec![
                "нет".into(),
                "основной (всегда первым)".into(),
                "запасной (если основной недоступен)".into(),
            ],
            selected,
            kind: SelectKind::Role(server.id),
        });
    }

    /// `index`: 0 none, 1 primary, 2 backup. There is at most one server per role.
    pub(super) fn set_role(&mut self, id: u64, index: usize) {
        let role = match index {
            1 => Some(ServerRole::Primary),
            2 => Some(ServerRole::Backup),
            _ => None,
        };
        let Some((_, key)) = self.server_key_of(id) else {
            return;
        };
        // One primary and one backup at most: the previous holder of the role loses it.
        let mut displaced = Vec::new();
        if let Some(r) = role {
            for (group, server) in self
                .subs
                .iter_mut()
                .flat_map(|s| s.servers.iter_mut().map(|x| (s.name.clone(), x)))
            {
                if server.id != id && server.role == Some(r) {
                    server.role = None;
                    displaced.push(override_key(&group, server));
                }
            }
        }
        for k in displaced {
            self.update_override(&k, |o| o.role = None);
        }
        let mut name = String::new();
        for server in self
            .subs
            .iter_mut()
            .flat_map(|s| s.servers.iter_mut())
            .filter(|s| s.id == id)
        {
            server.role = role;
            name = server.name.clone();
        }
        self.update_override(&key, |o| o.role = role);
        self.log(
            Level::Info,
            format!("роль {name}: {}", role.map_or("нет", |r| r.label())),
        );
        self.save_config();
        self.restart_if_affected(id);
    }

    pub(super) fn toggle_fragment(&mut self) {
        let Some(server) = self.selected_server() else {
            self.status = Some("Выберите сервер (не группу)".into());
            return;
        };
        if !server.is_supported() || !matches!(server.security, Security::Tls | Security::Reality) {
            self.status = Some("Фрагментация применима только к серверам с TLS или Reality".into());
            return;
        }
        let (id, on) = (server.id, !server.fragment);
        self.set_fragment(id, on);
    }

    pub(super) fn set_fragment(&mut self, id: u64, on: bool) {
        let Some((_, key)) = self.server_key_of(id) else {
            return;
        };
        let mut name = String::new();
        for server in self
            .subs
            .iter_mut()
            .flat_map(|s| s.servers.iter_mut())
            .filter(|s| s.id == id)
        {
            server.fragment = on;
            name = server.name.clone();
        }
        self.update_override(&key, |o| o.fragment = on);
        self.log(
            Level::Info,
            format!(
                "фрагментация ClientHello для {name}: {}",
                if on { "вкл" } else { "выкл" }
            ),
        );
        self.save_config();
        self.restart_if_affected(id);
    }

    /// Reconnects when the change touches the running connection: the connected server
    /// itself, or the backup of a connected primary.
    fn restart_if_affected(&mut self, id: u64) {
        let (Conn::Connected(c) | Conn::Connecting(c)) = self.conn else {
            return;
        };
        let affected = c == id || self.backup_for(c).is_some_and(|b| b.id == id);
        // A role change can also start or end a pairing for the connected server.
        let primary_changed = self
            .server_by_id(c)
            .is_some_and(|s| s.role == Some(ServerRole::Primary));
        if !(affected || primary_changed) {
            return;
        }
        if self.busy {
            self.status = Some("Изменение применится при следующем подключении".into());
        } else {
            self.connect(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::unbounded_channel;

    const REALITY: &str =
        "vless://u@h.example.com:443?security=reality&sni=x.org&pbk=K&sid=ab&fp=chrome#R";

    fn app_with(links: &[&str]) -> (AppState, Vec<u64>) {
        let dir = std::env::temp_dir().join(format!(
            "elf-gate-opts-{}-{}",
            std::process::id(),
            links.len()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let (tx, _rx) = unbounded_channel();
        let mut a = AppState::build(tx, Config::default(), Some(Storage::new(dir)), false);
        for l in links {
            a.submit_input((*l).into());
        }
        let ids = a.subs[0].servers.iter().map(|s| s.id).collect();
        (a, ids)
    }

    #[tokio::test]
    async fn only_one_server_holds_each_role() {
        let (mut a, ids) = app_with(&[
            REALITY,
            &REALITY
                .replace("#R", "#R2")
                .replace("h.example", "h2.example"),
        ]);
        a.set_role(ids[0], 1);
        a.set_role(ids[1], 1);
        assert_eq!(
            a.server_by_id(ids[0]).unwrap().role,
            None,
            "the first lost it"
        );
        assert_eq!(
            a.server_by_id(ids[1]).unwrap().role,
            Some(ServerRole::Primary)
        );
        assert_eq!(
            a.config
                .overrides
                .iter()
                .filter(|o| o.role.is_some())
                .count(),
            1,
            "and so does config.toml"
        );
        // Clearing removes the entry completely.
        a.set_role(ids[1], 0);
        assert!(a.config.overrides.is_empty());
    }

    #[tokio::test]
    async fn the_backup_is_found_for_the_primary_only() {
        let (mut a, ids) = app_with(&[
            REALITY,
            &REALITY
                .replace("#R", "#R2")
                .replace("h.example", "h2.example"),
        ]);
        a.set_role(ids[0], 1);
        a.set_role(ids[1], 2);
        assert_eq!(a.backup_for(ids[0]).unwrap().id, ids[1]);
        assert!(
            a.backup_for(ids[1]).is_none(),
            "connecting to the backup directly has no pair"
        );
    }

    #[tokio::test]
    async fn roles_and_fragmentation_survive_a_restart_and_leave_the_link_alone() {
        let (mut a, ids) = app_with(&[REALITY]);
        a.set_role(ids[0], 2);
        a.set_fragment(ids[0], true);
        let storage = a.storage.clone().unwrap();
        let text = std::fs::read_to_string(storage.config_path()).unwrap();
        assert!(
            text.contains("role = \"backup\"") && text.contains("fragment = true"),
            "{text}"
        );
        assert_eq!(a.config.servers[0].link, REALITY);

        let (tx, _rx) = unbounded_channel();
        let b = AppState::build(tx, storage.load().unwrap(), Some(storage), false);
        let s = &b.subs[0].servers[0];
        assert_eq!(s.role, Some(ServerRole::Backup));
        assert!(s.fragment);
    }

    #[tokio::test]
    async fn fragmentation_is_for_tls_and_reality_only() {
        let (mut a, _) = app_with(&["vless://u@10.0.0.5:443?security=none#Plain"]);
        a.selected = 1;
        a.toggle_fragment();
        assert!(a.status.as_deref().unwrap().contains("TLS или Reality"));
    }
}
