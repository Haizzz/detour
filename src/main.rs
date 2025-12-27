//! Detour - A performance focused DNS proxy.
//!
//! Forwards DNS queries to an upstream server without caching or filtering.
//! Supports both UDP and TCP transports.

mod proxy;
mod transport;

use clap::Parser;
use std::io;
use std::net::SocketAddr;

/// Command line arguments for the DNS proxy.
#[derive(Parser)]
#[command(name = "detour")]
#[command(about = "Performance focused DNS proxy", long_about = None)]
struct Args {
    /// Local port to listen on
    #[arg(short, long, default_value = "5353")]
    port: u16,

    /// Bind address
    #[arg(short, long, default_value = "127.0.0.1")]
    bind: String,

    /// Upstream DNS server (host:port)
    #[arg(short, long, default_value = "8.8.8.8:53")]
    upstream: String,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let bind_addr: SocketAddr = format!("{}:{}", args.bind, args.port)
        .parse()
        .expect("invalid bind address");

    let upstream_addr: SocketAddr = args.upstream.parse().expect("invalid upstream address");

    let config = proxy::ProxyConfig {
        bind_addr,
        upstream_addr,
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, proxy::run(config))
}
