//! TCP transport for DNS queries.
//!
//! Handles DNS queries over TCP. Each client connection is handled
//! independently - we read the query, race to multiple upstreams, and return
//! the first response. TCP DNS messages are prefixed with a 2-byte length.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::resolver::{QueryAction, Resolver};

use super::{MAX_DNS_PACKET_SIZE, Protocol, QueryLogger};

/// TCP transport for DNS proxy.
pub struct TcpTransport {
    listener: TcpListener,
}

impl TcpTransport {
    /// Bind a TCP listener for the transport.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { listener })
    }

    /// Start the TCP transport.
    pub fn start(self, upstreams: Vec<SocketAddr>, resolver: Arc<Resolver>, verbose: bool) {
        tokio::spawn(run_accept_loop(self.listener, upstreams, resolver, verbose));
    }
}

async fn run_accept_loop(
    listener: TcpListener,
    upstreams: Vec<SocketAddr>,
    resolver: Arc<Resolver>,
    verbose: bool,
) {
    loop {
        match listener.accept().await {
            Ok((client, _)) => {
                let resolver = resolver.clone();
                let upstreams = upstreams.clone();
                tokio::spawn(handle_connection(client, upstreams, resolver, verbose));
            }
            Err(e) => {
                eprintln!("TCP accept error: {}", e);
            }
        }
    }
}

async fn handle_connection(
    mut client: TcpStream,
    upstreams: Vec<SocketAddr>,
    resolver: Arc<Resolver>,
    verbose: bool,
) {
    let start_time = Instant::now();
    let logger = QueryLogger::new(Protocol::Tcp);

    let query_with_len = match read_dns_message(&mut client).await {
        Some(q) => q,
        None => return,
    };

    if query_with_len.len() <= 2 {
        return;
    }
    let query = &query_with_len[2..];

    match resolver.process_query(query) {
        QueryAction::Invalid => (),
        QueryAction::Blocked { response, domain } => {
            send_tcp_response(&mut client, &response).await;
            if verbose {
                logger.blocked(&domain, start_time.elapsed().as_secs_f64() * 1000.0);
            }
        }
        QueryAction::Cached { response, domain } => {
            send_tcp_response(&mut client, &response).await;
            if verbose {
                logger.cached(&domain, start_time.elapsed().as_secs_f64() * 1000.0);
            }
        }
        QueryAction::Forward { domain } => {
            let upstream_start = Instant::now();
            if let Some((response, winner)) = race_upstreams(query, &upstreams).await {
                send_tcp_response(&mut client, &response).await;
                resolver.process_response(&response);
                if verbose {
                    logger.forwarded(
                        &domain,
                        start_time.elapsed().as_secs_f64() * 1000.0,
                        upstream_start.elapsed().as_secs_f64() * 1000.0,
                        winner,
                    );
                }
            }
        }
    }
}

async fn send_tcp_response(client: &mut TcpStream, response: &[u8]) {
    let len_prefix = (response.len() as u16).to_be_bytes();
    let _ = client.write_all(&len_prefix).await;
    let _ = client.write_all(response).await;
}

async fn read_dns_message(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; MAX_DNS_PACKET_SIZE];
    let mut total_read = 0;

    loop {
        match stream.read(&mut buf[total_read..]).await {
            Ok(0) => return None,
            Ok(n) => total_read += n,
            Err(_) => return None,
        }

        if total_read >= 2 {
            let msg_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if total_read >= 2 + msg_len {
                buf.truncate(total_read);
                return Some(buf);
            }
        }
    }
}

async fn race_upstreams(query: &[u8], upstreams: &[SocketAddr]) -> Option<(Vec<u8>, SocketAddr)> {
    if upstreams.is_empty() {
        return None;
    }

    if upstreams.len() == 1 {
        return forward_to_upstream(query, upstreams[0])
            .await
            .map(|r| (r, upstreams[0]));
    }

    use futures::future::select_all;

    let futures: Vec<_> = upstreams
        .iter()
        .map(|&addr| {
            let q = query.to_vec();
            Box::pin(async move { (forward_to_upstream(&q, addr).await, addr) })
        })
        .collect();

    let mut remaining = futures;
    while !remaining.is_empty() {
        let ((result, addr), _, rest) = select_all(remaining).await;
        if let Some(response) = result {
            return Some((response, addr));
        }
        remaining = rest;
    }
    None
}

async fn forward_to_upstream(query: &[u8], upstream_addr: SocketAddr) -> Option<Vec<u8>> {
    let mut upstream = TcpStream::connect(upstream_addr).await.ok()?;

    let len_prefix = (query.len() as u16).to_be_bytes();
    upstream.write_all(&len_prefix).await.ok()?;
    upstream.write_all(query).await.ok()?;

    let mut buf = vec![0u8; MAX_DNS_PACKET_SIZE];
    let mut total_read = 0;

    loop {
        match upstream.read(&mut buf[total_read..]).await {
            Ok(0) => break,
            Ok(n) => total_read += n,
            Err(_) => return None,
        }

        if total_read >= 2 {
            let msg_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if total_read >= 2 + msg_len {
                break;
            }
        }
    }

    if total_read <= 2 {
        return None;
    }

    Some(buf[2..total_read].to_vec())
}
