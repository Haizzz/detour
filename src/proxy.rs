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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_config_creation() {
        let bind_addr: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let upstream_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let config = ProxyConfig {
            bind_addr,
            upstream_addr,
        };

        assert_eq!(config.bind_addr.port(), 5353);
        assert_eq!(config.upstream_addr.port(), 53);
    }

    #[test]
    fn proxy_config_with_ipv4_addresses() {
        let bind_addr: SocketAddr = "0.0.0.0:53".parse().unwrap();
        let upstream_addr: SocketAddr = "1.1.1.1:53".parse().unwrap();

        let config = ProxyConfig {
            bind_addr,
            upstream_addr,
        };

        assert!(config.bind_addr.is_ipv4());
        assert!(config.upstream_addr.is_ipv4());
    }

    #[test]
    fn proxy_config_with_ipv6_addresses() {
        let bind_addr: SocketAddr = "[::1]:5353".parse().unwrap();
        let upstream_addr: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();

        let config = ProxyConfig {
            bind_addr,
            upstream_addr,
        };

        assert!(config.bind_addr.is_ipv6());
        assert!(config.upstream_addr.is_ipv6());
    }

    #[test]
    fn proxy_config_different_ports() {
        let bind_addr: SocketAddr = "127.0.0.1:15357".parse().unwrap();
        let upstream_addr: SocketAddr = "8.8.8.8:5353".parse().unwrap();

        let config = ProxyConfig {
            bind_addr,
            upstream_addr,
        };

        assert_eq!(config.bind_addr.port(), 15357);
        assert_eq!(config.upstream_addr.port(), 5353);
    }
}
