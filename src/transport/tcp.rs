//! TCP transport for DNS queries.
//!
//! Handles DNS queries over TCP. Each client connection is handled
//! independently - we read the query, forward to upstream, and return
//! the response. TCP DNS messages are prefixed with a 2-byte length.

use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
    pub fn start(self, upstream_addr: SocketAddr) {
        tokio::task::spawn_local(run_accept_loop(self.listener, upstream_addr));
    }
}

/// Accept loop - spawns a handler task for each incoming connection.
async fn run_accept_loop(listener: TcpListener, upstream_addr: SocketAddr) {
    loop {
        match listener.accept().await {
            Ok((client, _)) => {
                tokio::task::spawn_local(handle_connection(client, upstream_addr));
            }
            Err(e) => {
                eprintln!("TCP accept error: {}", e);
            }
        }
    }
}

/// Handle a single TCP connection: read query, forward, return response.
async fn handle_connection(mut client: TcpStream, upstream_addr: SocketAddr) {
    let query = match read_dns_message(&mut client).await {
        Some(q) => q,
        None => return,
    };

    let response = match forward_to_upstream(&query, upstream_addr).await {
        Some(r) => r,
        None => return,
    };

    let _ = client.write_all(&response).await;
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
async fn forward_to_upstream(query: &[u8], upstream_addr: SocketAddr) -> Option<Vec<u8>> {
    let mut upstream = TcpStream::connect(upstream_addr).await.ok()?;

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

    buf.truncate(total_read);

    Some(buf)
}
