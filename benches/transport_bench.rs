//! Benchmarks for TCP and UDP DNS request handling.
//!
//! Measures DNS proxy performance with simulated upstream latency.
//! Uses realistic latency based on public DNS benchmarks:
//! - Cloudflare (1.1.1.1): ~5-18ms average
//! - Google (8.8.8.8): ~7-24ms average
//! We simulate ~15ms average with ±5ms jitter.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::Rng;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::runtime::Runtime;
use tokio::task::LocalSet;

use detour::transport::tcp::TcpTransport;
use detour::transport::udp::UdpTransport;

const MAX_DNS_PACKET_SIZE: usize = 4096;

const TCP_PROXY_ADDR: &str = "127.0.0.1:15354";
const UDP_PROXY_ADDR: &str = "127.0.0.1:15355";
const TCP_UPSTREAM_ADDR: &str = "127.0.0.1:15356";
const UDP_UPSTREAM_ADDR: &str = "127.0.0.1:15357";

/// Simulated upstream latency (based on real-world DNS benchmarks)
const BASE_LATENCY_MS: u64 = 15;
const JITTER_MS: u64 = 5;

fn build_dns_query() -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&[0x12, 0x34]); // Query ID
    query.extend_from_slice(&[0x01, 0x00]); // Flags: standard query
    query.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    query.extend_from_slice(&[0x00, 0x00]); // Answer RRs: 0
    query.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
    query.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0
    // Query for "example.com"
    query.extend_from_slice(&[0x07]); // length of "example"
    query.extend_from_slice(b"example");
    query.extend_from_slice(&[0x03]); // length of "com"
    query.extend_from_slice(b"com");
    query.extend_from_slice(&[0x00]); // null terminator
    query.extend_from_slice(&[0x00, 0x01]); // Type: A
    query.extend_from_slice(&[0x00, 0x01]); // Class: IN
    query
}

fn build_tcp_dns_query() -> Vec<u8> {
    let query = build_dns_query();
    let len = query.len() as u16;
    let mut tcp_query = Vec::new();
    tcp_query.extend_from_slice(&len.to_be_bytes());
    tcp_query.extend_from_slice(&query);
    tcp_query
}

fn build_dns_response() -> Vec<u8> {
    let mut response = build_dns_query();
    response[2] = 0x81; // Response flag
    response[3] = 0x80; // Recursion available
    response[6] = 0x00; // Answer count
    response[7] = 0x01;
    // Answer: example.com A 93.184.216.34
    response.extend_from_slice(&[0xc0, 0x0c]); // Name pointer
    response.extend_from_slice(&[0x00, 0x01]); // Type: A
    response.extend_from_slice(&[0x00, 0x01]); // Class: IN
    response.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL: 300
    response.extend_from_slice(&[0x00, 0x04]); // Data length: 4
    response.extend_from_slice(&[93, 184, 216, 34]); // IP address
    response
}

fn build_tcp_dns_response() -> Vec<u8> {
    let response = build_dns_response();
    let len = response.len() as u16;
    let mut tcp_response = Vec::new();
    tcp_response.extend_from_slice(&len.to_be_bytes());
    tcp_response.extend_from_slice(&response);
    tcp_response
}

/// Simulate realistic upstream latency with jitter
async fn simulate_upstream_latency() {
    let jitter = rand::rng().random_range(0..=JITTER_MS * 2);
    let latency = BASE_LATENCY_MS - JITTER_MS + jitter;
    tokio::time::sleep(Duration::from_millis(latency)).await;
}

/// Mock TCP upstream with simulated latency
async fn mock_tcp_upstream(listener: TcpListener) {
    let response = build_tcp_dns_response();
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let response = response.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; MAX_DNS_PACKET_SIZE];
                if stream.read(&mut buf).await.is_ok() {
                    simulate_upstream_latency().await;
                    let _ = stream.write_all(&response).await;
                }
            });
        }
    }
}

/// Mock UDP upstream with simulated latency
async fn mock_udp_upstream(socket: UdpSocket) {
    let response = build_dns_response();
    let mut buf = [0u8; MAX_DNS_PACKET_SIZE];
    loop {
        if let Ok((_, src)) = socket.recv_from(&mut buf).await {
            simulate_upstream_latency().await;
            let _ = socket.send_to(&response, src).await;
        }
    }
}

fn start_tcp_mock_upstream() {
    let upstream_addr: SocketAddr = TCP_UPSTREAM_ADDR.parse().unwrap();

    std::thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let listener = TcpListener::bind(upstream_addr).await.unwrap();
            mock_tcp_upstream(listener).await;
        });
    });

    std::thread::sleep(Duration::from_millis(50));
}

fn start_udp_mock_upstream() {
    let upstream_addr: SocketAddr = UDP_UPSTREAM_ADDR.parse().unwrap();

    std::thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let socket = UdpSocket::bind(upstream_addr).await.unwrap();
            mock_udp_upstream(socket).await;
        });
    });

    std::thread::sleep(Duration::from_millis(50));
}

fn start_tcp_proxy() {
    let proxy_addr: SocketAddr = TCP_PROXY_ADDR.parse().unwrap();
    let upstream_addr: SocketAddr = TCP_UPSTREAM_ADDR.parse().unwrap();

    std::thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        let local = LocalSet::new();

        local.block_on(&rt, async {
            let transport = TcpTransport::bind(proxy_addr).await.unwrap();
            transport.start(upstream_addr);

            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });
    });

    std::thread::sleep(Duration::from_millis(50));
}

fn start_udp_proxy() {
    let proxy_addr: SocketAddr = UDP_PROXY_ADDR.parse().unwrap();
    let upstream_addr: SocketAddr = UDP_UPSTREAM_ADDR.parse().unwrap();

    std::thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        let local = LocalSet::new();

        local.block_on(&rt, async {
            let transport = UdpTransport::bind(proxy_addr).await.unwrap();
            transport.start(upstream_addr);

            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });
    });

    std::thread::sleep(Duration::from_millis(50));
}

fn bench_tcp_request(c: &mut Criterion) {
    start_tcp_mock_upstream();
    start_tcp_proxy();

    let rt = Runtime::new().unwrap();
    let proxy_addr: SocketAddr = TCP_PROXY_ADDR.parse().unwrap();

    let query = build_tcp_dns_query();
    let query_size = query.len() as u64;

    let mut group = c.benchmark_group("tcp");
    group.throughput(Throughput::Elements(1));

    group.bench_function(BenchmarkId::new("request_handling", "latency"), |b| {
        b.to_async(&rt).iter(|| async {
            let mut client = TcpStream::connect(proxy_addr).await.unwrap();
            let query = build_tcp_dns_query();
            client.write_all(&query).await.unwrap();

            let mut buf = [0u8; MAX_DNS_PACKET_SIZE];
            let mut total = 0;
            loop {
                let n = client.read(&mut buf[total..]).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if total >= 2 {
                    let msg_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    if total >= 2 + msg_len {
                        break;
                    }
                }
            }
            total
        });
    });

    group.throughput(Throughput::Bytes(query_size));
    group.bench_function(BenchmarkId::new("request_handling", "bytes"), |b| {
        b.to_async(&rt).iter(|| async {
            let mut client = TcpStream::connect(proxy_addr).await.unwrap();
            let query = build_tcp_dns_query();
            client.write_all(&query).await.unwrap();

            let mut buf = [0u8; MAX_DNS_PACKET_SIZE];
            let mut total = 0;
            loop {
                let n = client.read(&mut buf[total..]).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if total >= 2 {
                    let msg_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    if total >= 2 + msg_len {
                        break;
                    }
                }
            }
            total
        });
    });

    group.finish();
}

fn bench_udp_request(c: &mut Criterion) {
    start_udp_mock_upstream();
    start_udp_proxy();

    let rt = Runtime::new().unwrap();
    let proxy_addr: SocketAddr = UDP_PROXY_ADDR.parse().unwrap();

    let query = build_dns_query();
    let query_size = query.len() as u64;

    let mut group = c.benchmark_group("udp");
    group.throughput(Throughput::Elements(1));

    group.bench_function(BenchmarkId::new("request_handling", "latency"), |b| {
        b.to_async(&rt).iter(|| async {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let query = build_dns_query();
            client.send_to(&query, proxy_addr).await.unwrap();

            let mut buf = [0u8; MAX_DNS_PACKET_SIZE];
            tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap()
                .0
        });
    });

    group.throughput(Throughput::Bytes(query_size));
    group.bench_function(BenchmarkId::new("request_handling", "bytes"), |b| {
        b.to_async(&rt).iter(|| async {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let query = build_dns_query();
            client.send_to(&query, proxy_addr).await.unwrap();

            let mut buf = [0u8; MAX_DNS_PACKET_SIZE];
            tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap()
                .0
        });
    });

    group.finish();
}

criterion_group!(benches, bench_tcp_request, bench_udp_request);
criterion_main!(benches);
