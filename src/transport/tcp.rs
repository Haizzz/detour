//! TCP transport for DNS queries.
//!
//! Handles DNS queries over TCP. Each client connection is handled
//! independently - we read the query, forward to upstream, and return
//! the response. TCP DNS messages are prefixed with a 2-byte length.

use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::resolver::{QueryAction, Resolver};

use super::MAX_DNS_PACKET_SIZE;

/// TCP transport for DNS proxy.
///
/// Binds to a local address and accepts connections from clients.
/// Each connection is handled in a separate task.
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
    ///
    /// Spawns an accept loop that handles each connection in a separate task.
    pub fn start(self, upstream_addr: SocketAddr, resolver: Rc<Resolver>) {
        tokio::task::spawn_local(run_accept_loop(self.listener, upstream_addr, resolver));
    }
}

/// Accept loop - spawns a handler task for each incoming connection.
async fn run_accept_loop(listener: TcpListener, upstream_addr: SocketAddr, resolver: Rc<Resolver>) {
    loop {
        match listener.accept().await {
            Ok((client, _)) => {
                let resolver = resolver.clone();
                tokio::task::spawn_local(handle_connection(client, upstream_addr, resolver));
            }
            Err(e) => {
                eprintln!("TCP accept error: {}", e);
            }
        }
    }
}

/// Handle a single TCP connection: read query, process through resolver, respond.
async fn handle_connection(
    mut client: TcpStream,
    upstream_addr: SocketAddr,
    resolver: Rc<Resolver>,
) {
    let query_with_len = match read_dns_message(&mut client).await {
        Some(q) => q,
        None => return,
    };

    // TCP DNS: first 2 bytes are length prefix, actual DNS query starts at byte 2
    if query_with_len.len() <= 2 {
        return;
    }
    let query = &query_with_len[2..];

    // Ask resolver what to do with this query
    match resolver.process_query(query) {
        QueryAction::Blocked(response) => {
            send_tcp_response(&mut client, &response).await;
        }
        QueryAction::Forward => {
            if let Some(response) = forward_to_upstream(query, upstream_addr).await {
                // Notify resolver of response (for caching, etc.)
                resolver.process_response(query, &response);
                send_tcp_response(&mut client, &response).await;
            }
        }
    }
}

/// Send a DNS response over TCP with length prefix.
async fn send_tcp_response(client: &mut TcpStream, response: &[u8]) {
    let len_prefix = (response.len() as u16).to_be_bytes();
    let _ = client.write_all(&len_prefix).await;
    let _ = client.write_all(response).await;
}

/// Read a length-prefixed DNS message from a TCP stream.
///
/// TCP DNS messages start with a 2-byte big-endian length prefix.
/// Returns the complete message including the length prefix.
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

/// Forward a DNS query to the upstream server and return the response.
///
/// Query should NOT include the TCP length prefix.
/// Returns the response WITHOUT length prefix.
async fn forward_to_upstream(query: &[u8], upstream_addr: SocketAddr) -> Option<Vec<u8>> {
    let mut upstream = TcpStream::connect(upstream_addr).await.ok()?;

    // Send with length prefix
    let len_prefix = (query.len() as u16).to_be_bytes();
    upstream.write_all(&len_prefix).await.ok()?;
    upstream.write_all(query).await.ok()?;

    // Read response
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

    // Return without length prefix
    Some(buf[2..total_read].to_vec())
}
