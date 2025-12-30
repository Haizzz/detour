//! DNS proxy orchestration.
//!
//! Binds transports and runs the proxy server.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::filter::Blocklist;
use crate::resolver::Resolver;
use crate::transport::{tcp::TcpTransport, udp::UdpTransport};

/// Configuration for the DNS proxy.
pub struct ProxyConfig {
    /// Local address to bind (e.g., 127.0.0.1:5353)
    pub bind_addr: SocketAddr,
    /// Upstream DNS server addresses (races all, uses first response)
    pub upstreams: Vec<SocketAddr>,
    /// Enable verbose logging (domain, blocked status, timing)
    pub verbose: bool,
}

/// Run the DNS proxy with the given configuration.
///
/// Starts UDP and TCP transports on the bind address and forwards
/// all queries to the upstream server. Runs indefinitely.
pub async fn run(config: ProxyConfig) -> io::Result<()> {
    let blocklist = Blocklist::new();
    let resolver = Arc::new(Resolver::new(blocklist));

    println!(
        "DNS proxy listening on {} ({} domains blocked)",
        config.bind_addr,
        resolver.blocked_count()
    );
    let upstream_strs: Vec<_> = config.upstreams.iter().map(|a| a.to_string()).collect();
    println!("Racing upstreams: {}", upstream_strs.join(", "));

    let udp = UdpTransport::bind(config.bind_addr, config.upstreams.len()).await?;
    let tcp = TcpTransport::bind(config.bind_addr).await?;

    udp.start(config.upstreams.clone(), resolver.clone(), config.verbose);
    tcp.start(config.upstreams, resolver.clone(), config.verbose);

    // Print stats every minute
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await; // Skip first immediate tick
        loop {
            interval.tick().await;
            let stats = resolver.stats_snapshot_and_reset();
            let cache_len = resolver.cache_len();
            println!(
                "[stats] uptime={}s cache={} requests={} forwarded={} cached={} blocked={} avg_response={:.2}ms",
                stats.uptime_secs,
                cache_len,
                stats.requests,
                stats.forwarded,
                stats.cached,
                stats.blocked,
                stats.avg_response_ms
            );
        }
    });

    // Keep running forever
    std::future::pending::<()>().await;

    Ok(())
}
