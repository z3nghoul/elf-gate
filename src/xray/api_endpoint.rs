//! Where the core's API listens. Its `RoutingService` can change the routing of the whole
//! machine, so no other program may reach it: on Linux the API input is a unix socket with
//! mode 0600 in the private run folder, everywhere else (Windows, or a folder name too long
//! for a socket) a random port on 127.0.0.1 chosen anew for every start of the core, never a
//! fixed one.

use std::path::{Path, PathBuf};

/// The longest path a unix socket takes (`sun_path` is 108 bytes with the end mark).
const MAX_SOCKET_PATH: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiEndpoint {
    /// A unix socket file, created by the core with mode 0600.
    Unix(PathBuf),
    /// `127.0.0.1:<port>`.
    Tcp(u16),
}

impl ApiEndpoint {
    /// The endpoint for a new core. `run_dir` is the private folder the core's files live in.
    pub fn choose(run_dir: &Path) -> Self {
        Self::choose_with(run_dir, cfg!(unix), random_free_port)
    }

    fn choose_with(run_dir: &Path, unix: bool, port: impl FnOnce() -> u16) -> Self {
        let socket = run_dir.join("api.sock");
        if unix && socket.as_os_str().len() <= MAX_SOCKET_PATH {
            Self::Unix(socket)
        } else {
            Self::Tcp(port())
        }
    }

    /// The `listen` value of the API inbound, and its port (a socket has none).
    pub fn listen(&self) -> (String, Option<u16>) {
        match self {
            // The mode after the comma is Xray's own syntax for the socket file.
            Self::Unix(path) => (format!("{},0600", path.display()), None),
            Self::Tcp(port) => ("127.0.0.1".into(), Some(*port)),
        }
    }

    /// The `--server` value of `xray api ...`.
    pub fn server_arg(&self) -> String {
        match self {
            Self::Unix(path) => format!("unix://{}", path.display()),
            Self::Tcp(port) => format!("127.0.0.1:{port}"),
        }
    }

    /// A socket file left by an earlier core would stop the new one from listening.
    pub fn clear_stale(&self) {
        if let Self::Unix(path) = self {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// A port nobody listens on, asked of the system (port 0). Chosen again at every start, so a
/// program that learned an old one finds nothing there.
fn random_free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_unix_the_api_is_a_socket_in_the_run_folder_with_mode_0600() {
        // The expected path is built the way the code builds it: `join` uses the separator
        // of the system the test runs on.
        let run_dir = Path::new("/home/u/.local/state/elf-gate/run");
        let socket = run_dir.join("api.sock");
        let e = ApiEndpoint::choose_with(run_dir, true, || 1);
        assert_eq!(e, ApiEndpoint::Unix(socket.clone()));
        let (listen, port) = e.listen();
        assert_eq!(listen, format!("{},0600", socket.display()));
        assert_eq!(port, None);
        assert_eq!(e.server_arg(), format!("unix://{}", socket.display()));
    }

    #[test]
    fn without_sockets_or_with_a_long_path_it_is_a_local_port_that_is_not_fixed() {
        let short = Path::new("C:/Users/u/AppData/Roaming/elf-gate/run");
        assert_eq!(
            ApiEndpoint::choose_with(short, false, || 4242),
            ApiEndpoint::Tcp(4242)
        );
        let long = PathBuf::from("/a".repeat(60));
        assert_eq!(
            ApiEndpoint::choose_with(&long, true, || 4243),
            ApiEndpoint::Tcp(4243)
        );
        let e = ApiEndpoint::Tcp(4243);
        assert_eq!(e.listen(), ("127.0.0.1".to_string(), Some(4243)));
        assert_eq!(e.server_arg(), "127.0.0.1:4243");
        // The system gives a different port on a later ask, and never the old fixed one.
        let ports: std::collections::BTreeSet<u16> = (0..5).map(|_| random_free_port()).collect();
        assert!(ports.iter().all(|p| *p != 0 && *p != 10085), "{ports:?}");
    }
}
