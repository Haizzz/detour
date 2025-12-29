//! Detour - A performance focused DNS proxy.
//!
//! Forwards DNS queries to an upstream server with optional ad-blocking.
//! Supports both UDP and TCP transports.

mod filter;
mod proxy;
mod resolver;
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

    /// Upstream DNS servers (host:port), races all and uses first response
    #[arg(short, long, default_values_t = ["8.8.8.8:53".to_string(), "1.1.1.1:53".to_string()])]
    upstream: Vec<String>,

    /// Print verbose logging (domain, blocked status, timing)
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let bind_addr: SocketAddr = format!("{}:{}", args.bind, args.port)
        .parse()
        .expect("invalid bind address");

    let upstreams: Vec<SocketAddr> = args
        .upstream
        .iter()
        .map(|s| s.parse().expect("invalid upstream address"))
        .collect();

    let config = proxy::ProxyConfig {
        bind_addr,
        upstreams,
        verbose: args.verbose,
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, proxy::run(config))
}
