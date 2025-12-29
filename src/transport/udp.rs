//! UDP transport for DNS queries.
//!
//! Handles connectionless DNS queries over UDP. Since UDP is stateless,
//! we track pending queries by their 16-bit query ID to route responses
//! back to the correct client.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::resolver::{QueryAction, Resolver};

use super::MAX_DNS_PACKET_SIZE;

/// UDP transport for DNS proxy.
///
/// Binds to a local address and forwards queries to an upstream DNS server.
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    upstream_socket: Arc<UdpSocket>,
}

impl UdpTransport {
    /// Bind UDP sockets for the transport.
    ///
    /// Creates a listening socket on `addr` and a separate socket for
    /// communicating with the upstream server.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let upstream_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

        Ok(Self {
            socket,
            upstream_socket,
        })
    }

    /// Start the UDP transport.
    ///
    /// Spawns a single async task that handles both directions using select.
    pub fn start(self, upstream_addr: SocketAddr, resolver: Rc<Resolver>) {
        tokio::task::spawn_local(run(
            self.socket,
            self.upstream_socket,
            upstream_addr,
            resolver,
        ));
    }
}

/// Main event loop for UDP transport.
///
/// Uses select to multiplex between client and upstream sockets,
/// forwarding queries and routing responses by query ID.
async fn run(
    socket: Arc<UdpSocket>,
    upstream: Arc<UdpSocket>,
    upstream_addr: SocketAddr,
    resolver: Rc<Resolver>,
) {
    let mut pending: HashMap<u16, SocketAddr> = HashMap::new();
    let mut client_buf = [0u8; MAX_DNS_PACKET_SIZE];
    let mut upstream_buf = [0u8; MAX_DNS_PACKET_SIZE];

    loop {
        tokio::select! {
            result = socket.recv_from(&mut client_buf) => {
                let (len, src) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("UDP recv error: {}", e);
                        continue;
                    }
                };

                if len < 12 {
                    continue;
                }

                let query = &client_buf[..len];

                // Ask resolver what to do with this query
                match resolver.process_query(query) {
                    QueryAction::Blocked(response) => {
                        let _ = socket.send_to(&response, src).await;
                        continue;
                    }
                    QueryAction::Forward => {
                        let query_id = u16::from_be_bytes([client_buf[0], client_buf[1]]);
                        pending.insert(query_id, src);

                        if let Err(e) = upstream.send_to(query, upstream_addr).await {
                            eprintln!("UDP forward error: {}", e);
                        }
                    }
                }
            }
            result = upstream.recv_from(&mut upstream_buf) => {
                let (len, _) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("UDP upstream recv error: {}", e);
                        continue;
                    }
                };

                if len < 12 {
                    continue;
                }

                let query_id = u16::from_be_bytes([upstream_buf[0], upstream_buf[1]]);

                if let Some(client_addr) = pending.remove(&query_id) {
                    // Notify resolver of response (for caching, etc.)
                    resolver.process_response(&[], &upstream_buf[..len]);

                    if let Err(e) = socket.send_to(&upstream_buf[..len], client_addr).await {
                        eprintln!("UDP response error: {}", e);
                    }
                }
            }
        }
    }
}
