//! Detour - A performance focused DNS proxy.
//!
//! Forwards DNS queries to an upstream server with optional ad-blocking.
//! Supports both UDP and TCP transports.

mod cache;
mod dns;
mod filter;
mod proxy;
mod resolver;
mod stats;
mod transport;

use clap::{Parser, Subcommand};
use std::io;
use std::net::SocketAddr;

#[derive(Parser)]
#[command(name = "detour")]
#[command(about = "Performance focused DNS proxy", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Local port to listen on
    #[arg(short, long, default_value = "53")]
    port: u16,

    /// Bind address
    #[arg(short, long, default_value = "127.0.0.1")]
    bind: String,

    /// Upstream DNS servers (host:port), races all and uses first response
    #[arg(short, long, default_values_t = [
        "1.1.1.1:53".to_string(),
        "1.0.0.1:53".to_string(),
        "8.8.8.8:53".to_string(),
        "8.8.4.4:53".to_string(),
    ])]
    upstream: Vec<String>,

    /// Print verbose logging (domain, blocked status, timing)
    #[arg(short, long)]
    verbose: bool,

    /// Number of worker threads (default: 2 per CPU core, minimum 2)
    #[arg(short, long)]
    workers: Option<usize>,
}

#[derive(Subcommand)]
enum Command {
    /// Install detour as a systemd service
    Install,
    /// Uninstall the systemd service
    Uninstall,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    if let Some(cmd) = args.command {
        return match cmd {
            Command::Install => install_service(),
            Command::Uninstall => uninstall_service(),
        };
    }

    let bind_addr: SocketAddr = format!("{}:{}", args.bind, args.port)
        .parse()
        .expect("invalid bind address");

    let upstreams: Vec<SocketAddr> = args
        .upstream
        .iter()
        .map(|s| s.parse().expect("invalid upstream address"))
        .collect();

    let workers = args.workers.unwrap_or_else(|| {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        cores * 2
    });

    let config = proxy::ProxyConfig {
        bind_addr,
        upstreams,
        verbose: args.verbose,
        workers,
    };

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.workers)
        .enable_all()
        .build()?
        .block_on(proxy::run(config))
}

const SERVICE_FILE: &str = include_str!("../detour.service");

fn install_service() -> io::Result<()> {
    use std::process::Command;

    let exe = std::env::current_exe()?;
    let bin_path = "/usr/local/bin/detour";
    let service_path = "/etc/systemd/system/detour.service";

    println!("Stopping existing service (if any)...");
    let _ = Command::new("systemctl").args(["stop", "detour"]).status();

    println!("Copying {} to {}", exe.display(), bin_path);
    std::fs::copy(&exe, bin_path)?;

    println!("Writing service file to {}", service_path);
    std::fs::write(service_path, SERVICE_FILE)?;

    println!("Enabling and starting service...");
    Command::new("systemctl").args(["daemon-reload"]).status()?;
    Command::new("systemctl")
        .args(["enable", "--now", "detour"])
        .status()?;

    println!("Done! Check status with: systemctl status detour");
    Ok(())
}

fn uninstall_service() -> io::Result<()> {
    use std::process::Command;

    println!("Stopping and disabling service...");
    let _ = Command::new("systemctl")
        .args(["disable", "--now", "detour"])
        .status();

    let _ = std::fs::remove_file("/etc/systemd/system/detour.service");
    let _ = std::fs::remove_file("/usr/local/bin/detour");

    Command::new("systemctl").args(["daemon-reload"]).status()?;

    println!("Uninstalled.");
    Ok(())
}
