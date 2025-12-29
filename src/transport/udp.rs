//! UDP transport for DNS queries.
//!
//! Handles connectionless DNS queries over UDP. Since UDP is stateless,
//! we track pending queries by their 16-bit query ID to route responses
//! back to the correct client. Races queries to multiple upstreams.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;

use crate::resolver::{QueryAction, Resolver};

use super::MAX_DNS_PACKET_SIZE;

fn log_blocked(domain: &str, elapsed_ms: f64) {
    println!("[UDP] {} BLOCKED total={:.3}ms", domain, elapsed_ms);
}

fn log_forwarded(domain: &str, elapsed_ms: f64, from: SocketAddr) {
    println!("[UDP] {} FORWARDED total={:.3}ms (from {})", domain, elapsed_ms, from);
}

/// UDP transport for DNS proxy.
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    upstream_sockets: Vec<Arc<UdpSocket>>,
}

impl UdpTransport {
    /// Bind UDP sockets for the transport.
    pub async fn bind(addr: SocketAddr, upstream_count: usize) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let mut upstream_sockets = Vec::with_capacity(upstream_count);
        for _ in 0..upstream_count {
            upstream_sockets.push(Arc::new(UdpSocket::bind("0.0.0.0:0").await?));
        }
        Ok(Self { socket, upstream_sockets })
    }

    /// Start the UDP transport.
    pub fn start(self, upstreams: Vec<SocketAddr>, resolver: Rc<Resolver>, verbose: bool) {
        tokio::task::spawn_local(run(
            self.socket,
            self.upstream_sockets,
            upstreams,
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

async fn run(
    socket: Arc<UdpSocket>,
    upstream_sockets: Vec<Arc<UdpSocket>>,
    upstreams: Vec<SocketAddr>,
    resolver: Rc<Resolver>,
    verbose: bool,
) {
    let mut pending: HashMap<u16, PendingQuery> = HashMap::new();
    let mut client_buf = [0u8; MAX_DNS_PACKET_SIZE];
    let mut upstream_bufs: Vec<[u8; MAX_DNS_PACKET_SIZE]> =
        vec![[0u8; MAX_DNS_PACKET_SIZE]; upstream_sockets.len()];

    loop {
        tokio::select! {
            biased;

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

                match resolver.process_query(query) {
                    QueryAction::Blocked { response, domain } => {
                        let _ = socket.send_to(&response, src).await;
                        if verbose {
                            log_blocked(&domain, start_time.elapsed().as_secs_f64() * 1000.0);
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

                        for (i, upstream_addr) in upstreams.iter().enumerate() {
                            if let Err(e) = upstream_sockets[i].send_to(query, upstream_addr).await {
                                eprintln!("UDP forward error to {}: {}", upstream_addr, e);
                            }
                        }
                    }
                }
            }

            result = recv_from_any(&upstream_sockets, &mut upstream_bufs) => {
                let (sock_idx, len, from_addr) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("UDP upstream recv error: {}", e);
                        continue;
                    }
                };

                if len < 12 {
                    continue;
                }

                let response = &upstream_bufs[sock_idx][..len];
                let query_id = u16::from_be_bytes([response[0], response[1]]);

                if let Some(pq) = pending.remove(&query_id) {
                    resolver.process_response(&[], response);

                    if let Err(e) = socket.send_to(response, pq.client_addr).await {
                        eprintln!("UDP response error: {}", e);
                    }

                    if verbose {
                        log_forwarded(&pq.domain, pq.start_time.elapsed().as_secs_f64() * 1000.0, from_addr);
                    }
                }
            }
        }
    }
}

async fn recv_from_any(
    sockets: &[Arc<UdpSocket>],
    bufs: &mut [[u8; MAX_DNS_PACKET_SIZE]],
) -> io::Result<(usize, usize, SocketAddr)> {
    use std::future::poll_fn;
    use std::task::Poll;

    poll_fn(|cx| {
        for (i, socket) in sockets.iter().enumerate() {
            let mut buf = tokio::io::ReadBuf::new(&mut bufs[i]);
            match socket.poll_recv_from(cx, &mut buf) {
                Poll::Ready(Ok(addr)) => {
                    return Poll::Ready(Ok((i, buf.filled().len(), addr)));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => continue,
            }
        }
        Poll::Pending
    })
    .await
}
