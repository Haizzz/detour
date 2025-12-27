use clap::Parser;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

const MAX_DNS_PACKET_SIZE: usize = 4096;

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

type PendingQueries = Arc<Mutex<HashMap<u16, SocketAddr>>>;

async fn handle_udp_client_to_upstream(
    socket: Arc<UdpSocket>,
    upstream: Arc<UdpSocket>,
    upstream_addr: SocketAddr,
    pending: PendingQueries,
) {
    let mut buf = [0u8; MAX_DNS_PACKET_SIZE];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("UDP recv error: {}", e);
                continue;
            }
        };

        if len < 12 {
            continue;
        }

        let query_id = u16::from_be_bytes([buf[0], buf[1]]);
        pending.lock().await.insert(query_id, src);

        if let Err(e) = upstream.send_to(&buf[..len], upstream_addr).await {
            eprintln!("UDP forward error: {}", e);
        }
    }
}

async fn handle_udp_upstream_to_client(
    socket: Arc<UdpSocket>,
    upstream: Arc<UdpSocket>,
    pending: PendingQueries,
) {
    let mut buf = [0u8; MAX_DNS_PACKET_SIZE];

    loop {
        let (len, _) = match upstream.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("UDP upstream recv error: {}", e);
                continue;
            }
        };

        if len < 12 {
            continue;
        }

        let query_id = u16::from_be_bytes([buf[0], buf[1]]);

        if let Some(client_addr) = pending.lock().await.remove(&query_id) {
            if let Err(e) = socket.send_to(&buf[..len], client_addr).await {
                eprintln!("UDP response error: {}", e);
            }
        }
    }
}

async fn handle_tcp_connection(mut client: TcpStream, upstream_addr: SocketAddr) {
    let mut query_buf = vec![0u8; MAX_DNS_PACKET_SIZE];
    let mut total_read = 0;

    loop {
        match client.read(&mut query_buf[total_read..]).await {
            Ok(0) => return,
            Ok(n) => total_read += n,
            Err(_) => return,
        }

        if total_read >= 2 {
            let msg_len = u16::from_be_bytes([query_buf[0], query_buf[1]]) as usize;
            if total_read >= 2 + msg_len {
                break;
            }
        }
    }

    let mut upstream = match TcpStream::connect(upstream_addr).await {
        Ok(s) => s,
        Err(_) => return,
    };

    if upstream.write_all(&query_buf[..total_read]).await.is_err() {
        return;
    }

    let mut response_buf = vec![0u8; MAX_DNS_PACKET_SIZE];
    let mut response_len = 0;

    loop {
        match upstream.read(&mut response_buf[response_len..]).await {
            Ok(0) => break,
            Ok(n) => response_len += n,
            Err(_) => return,
        }

        if response_len >= 2 {
            let msg_len = u16::from_be_bytes([response_buf[0], response_buf[1]]) as usize;
            if response_len >= 2 + msg_len {
                break;
            }
        }
    }

    let _ = client.write_all(&response_buf[..response_len]).await;
}

async fn run(args: Args) -> io::Result<()> {
    let bind_addr: SocketAddr = format!("{}:{}", args.bind, args.port)
        .parse()
        .expect("invalid bind address");

    let upstream_addr: SocketAddr = args.upstream.parse().expect("invalid upstream address");

    let udp_socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    let udp_upstream = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let tcp_listener = TcpListener::bind(bind_addr).await?;
    let pending: PendingQueries = Arc::new(Mutex::new(HashMap::new()));

    println!("DNS proxy listening on {}", bind_addr);
    println!("Forwarding to upstream: {}", args.upstream);

    tokio::task::spawn_local(handle_udp_client_to_upstream(
        udp_socket.clone(),
        udp_upstream.clone(),
        upstream_addr,
        pending.clone(),
    ));
    tokio::task::spawn_local(handle_udp_upstream_to_client(
        udp_socket,
        udp_upstream,
        pending,
    ));

    loop {
        let (client, _) = tcp_listener.accept().await?;
        tokio::task::spawn_local(handle_tcp_connection(client, upstream_addr));
    }
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, run(args))
}
