//! Sockets bound to one interface.

use std::net::SocketAddr;
use tokio::net::{TcpSocket, TcpStream};

pub fn can_bind(interface: &str) -> bool {
    TcpSocket::new_v4()
        .and_then(|s| s.bind_device(Some(interface.as_bytes())))
        .is_ok()
}

/// `SO_BINDTODEVICE` (allowed without privileges since Linux 5.7; older kernels refuse with
/// `PermissionDenied`, and the caller then does not trust a plain connect through the tunnel).
pub async fn connect_via(addr: SocketAddr, interface: &str) -> std::io::Result<TcpStream> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.bind_device(Some(interface.as_bytes()))?;
    socket.connect(addr).await
}
