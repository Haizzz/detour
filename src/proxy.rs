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
    /// Number of worker threads
    pub workers: usize,
    /// Custom blocklist file path (None = use embedded lists)
    pub blocklist_path: Option<String>,
}

/// Run the DNS proxy with the given configuration.
///
/// Starts UDP and TCP transports on the bind address and forwards
/// all queries to the upstream server. Runs indefinitely.
pub async fn run(config: ProxyConfig) -> io::Result<()> {
    let blocklist = match &config.blocklist_path {
        Some(path) => Blocklist::from_file(path)?,
        None => Blocklist::new(),
    };
    let resolver = Arc::new(Resolver::new(blocklist));

    println!(
        "DNS proxy listening on {} ({} domains blocked, {} workers)",
        config.bind_addr,
        resolver.blocked_count(),
        config.workers
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
            let cache_hit_pct = if stats.requests > 0 {
                (stats.cached as f64 / stats.requests as f64) * 100.0
            } else {
                0.0
            };
            println!(
                "[stats] cache={} requests={} forwarded={} cached={} blocked={} cache_hit={:.1}% avg_response={:.2}ms",
                cache_len,
                stats.requests,
                stats.forwarded,
                stats.cached,
                stats.blocked,
                cache_hit_pct,
                stats.avg_response_ms
            );
        }
    });

    // Keep running forever
    std::future::pending::<()>().await;

    Ok(())
}
