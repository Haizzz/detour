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
use std::time::Instant;
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
    pub fn start(self, upstream_addr: SocketAddr, resolver: Rc<Resolver>, verbose: bool) {
        tokio::task::spawn_local(run(
            self.socket,
            self.upstream_socket,
            upstream_addr,
            resolver,
            verbose,
        ));
    }
}

struct PendingQuery {
    client_addr: SocketAddr,
    domain: String,
    start_time: Instant,
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
    verbose: bool,
) {
    let mut pending: HashMap<u16, PendingQuery> = HashMap::new();
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

                let start_time = Instant::now();
                let query = &client_buf[..len];

                // Ask resolver what to do with this query
                match resolver.process_query(query) {
                    QueryAction::Blocked { response, domain } => {
                        let _ = socket.send_to(&response, src).await;
                        if verbose {
                            let elapsed = start_time.elapsed();
                            println!(
                                "[UDP] {} BLOCKED total={:.3}ms",
                                domain,
                                elapsed.as_secs_f64() * 1000.0
                            );
                        }
                        continue;
                    }
                    QueryAction::Forward { domain } => {
                        let query_id = u16::from_be_bytes([client_buf[0], client_buf[1]]);
                        pending.insert(query_id, PendingQuery {
                            client_addr: src,
                            domain,
                            start_time,
                        });

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

                if let Some(pq) = pending.remove(&query_id) {
                    // Notify resolver of response (for caching, etc.)
                    resolver.process_response(&[], &upstream_buf[..len]);

                    if let Err(e) = socket.send_to(&upstream_buf[..len], pq.client_addr).await {
                        eprintln!("UDP response error: {}", e);
                    }

                    if verbose {
                        let elapsed = pq.start_time.elapsed();
                        println!(
                            "[UDP] {} FORWARDED total={:.3}ms upstream={:.3}ms",
                            pq.domain,
                            elapsed.as_secs_f64() * 1000.0,
                            elapsed.as_secs_f64() * 1000.0
                        );
                    }
                }
            }
        }
    }
}
