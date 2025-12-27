//! DNS proxy orchestration.
//!
//! Binds transports and runs the proxy server.

use std::io;
use std::net::SocketAddr;

use crate::transport::{tcp::TcpTransport, udp::UdpTransport};

/// Configuration for the DNS proxy.
pub struct ProxyConfig {
    /// Local address to bind (e.g., 127.0.0.1:5353)
    pub bind_addr: SocketAddr,
    /// Upstream DNS server address (e.g., 8.8.8.8:53)
    pub upstream_addr: SocketAddr,
}

/// Run the DNS proxy with the given configuration.
///
/// Starts UDP and TCP transports on the bind address and forwards
/// all queries to the upstream server. Runs indefinitely.
pub async fn run(config: ProxyConfig) -> io::Result<()> {
    println!("DNS proxy listening on {}", config.bind_addr);
    println!("Forwarding to upstream: {}", config.upstream_addr);

    let udp = UdpTransport::bind(config.bind_addr).await?;
    let tcp = TcpTransport::bind(config.bind_addr).await?;

    udp.start(config.upstream_addr);
    tcp.start(config.upstream_addr);

    // Keep running forever
    std::future::pending::<()>().await;

    Ok(())
}
