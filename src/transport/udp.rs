//! UDP transport for DNS queries.
//!
//! Handles connectionless DNS queries over UDP. Since UDP is stateless,
//! we track pending queries by their 16-bit query ID to route responses
//! back to the correct client.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use super::MAX_DNS_PACKET_SIZE;

/// Maps DNS query IDs to client addresses for response routing.
type PendingQueries = Arc<Mutex<HashMap<u16, SocketAddr>>>;

/// UDP transport for DNS proxy.
///
/// Binds to a local address and forwards queries to an upstream DNS server.
/// Uses two internal tasks: one for client→upstream, one for upstream→client.
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    upstream_socket: Arc<UdpSocket>,
    pending: PendingQueries,
}

impl UdpTransport {
    /// Bind UDP sockets for the transport.
    ///
    /// Creates a listening socket on `addr` and a separate socket for
    /// communicating with the upstream server.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let upstream_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let pending = Arc::new(Mutex::new(HashMap::new()));

        Ok(Self {
            socket,
            upstream_socket,
            pending,
        })
    }

    /// Start the UDP transport.
    ///
    /// Spawns two async tasks:
    /// - One to receive queries from clients and forward to upstream
    /// - One to receive responses from upstream and send back to clients
    pub fn start(self, upstream_addr: SocketAddr) {
        tokio::task::spawn_local(run_client_to_upstream(
            self.socket.clone(),
            self.upstream_socket.clone(),
            upstream_addr,
            self.pending.clone(),
        ));

        tokio::task::spawn_local(run_upstream_to_client(
            self.socket,
            self.upstream_socket,
            self.pending,
        ));
    }
}

/// Receives queries from clients and forwards them to upstream.
async fn run_client_to_upstream(
    socket: Arc<UdpSocket>,
    upstream: Arc<UdpSocket>,
    upstream_addr: SocketAddr,
    pending: PendingQueries,
) {
    let mut buf = [0u8; MAX_DNS_PACKET_SIZE];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("UDP recv error: {}", e);
                continue;
            }
        };

        // DNS header is at least 12 bytes
        if len < 12 {
            continue;
        }

        // Extract query ID (first 2 bytes) for response routing
        let query_id = u16::from_be_bytes([buf[0], buf[1]]);
        pending.lock().await.insert(query_id, src);

        if let Err(e) = upstream.send_to(&buf[..len], upstream_addr).await {
            eprintln!("UDP forward error: {}", e);
        }
    }
}

/// Receives responses from upstream and sends them back to clients.
async fn run_upstream_to_client(
    socket: Arc<UdpSocket>,
    upstream: Arc<UdpSocket>,
    pending: PendingQueries,
) {
    let mut buf = [0u8; MAX_DNS_PACKET_SIZE];

    loop {
        let (len, _) = match upstream.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("UDP upstream recv error: {}", e);
                continue;
            }
        };

        if len < 12 {
            continue;
        }

        // Look up the original client by query ID
        let query_id = u16::from_be_bytes([buf[0], buf[1]]);

        if let Some(client_addr) = pending.lock().await.remove(&query_id) {
            if let Err(e) = socket.send_to(&buf[..len], client_addr).await {
                eprintln!("UDP response error: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_transport_binds_to_available_port() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let transport = UdpTransport::bind(addr).await;

        assert!(transport.is_ok());
    }

    #[tokio::test]
    async fn udp_transport_binds_to_specific_port() {
        let addr: SocketAddr = "127.0.0.1:15353".parse().unwrap();
        let transport = UdpTransport::bind(addr).await;

        assert!(transport.is_ok());
    }

    #[tokio::test]
    async fn udp_transport_fails_on_port_conflict() {
        let addr: SocketAddr = "127.0.0.1:15354".parse().unwrap();
        let _first = UdpTransport::bind(addr).await.unwrap();
        let second = UdpTransport::bind(addr).await;

        assert!(second.is_err());
    }

    #[test]
    fn dns_query_id_extraction() {
        let query_id: u16 = 0xABCD;
        let bytes = query_id.to_be_bytes();

        assert_eq!(bytes[0], 0xAB);
        assert_eq!(bytes[1], 0xCD);
        assert_eq!(u16::from_be_bytes(bytes), query_id);
    }

    #[test]
    fn minimum_dns_header_size() {
        let min_header = 12;
        let short_packet = [0u8; 11];
        let valid_packet = [0u8; 12];

        assert!(short_packet.len() < min_header);
        assert!(valid_packet.len() >= min_header);
    }
}
