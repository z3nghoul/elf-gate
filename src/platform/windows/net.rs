//! Sockets bound to one interface.

use std::net::SocketAddr;
use tokio::net::TcpStream;

pub fn can_bind(_interface: &str) -> bool {
    false
}

/// Not implemented on Windows yet (`IP_UNICAST_IF` needs the interface index and a Windows
/// machine to check it on): the caller falls back to measuring through the core.
pub async fn connect_via(_addr: SocketAddr, _interface: &str) -> std::io::Result<TcpStream> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "binding to an interface is not implemented on Windows",
    ))
}
