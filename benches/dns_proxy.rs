//! Benchmarks for the DNS proxy.
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use std::collections::HashMap;
use std::hint::black_box as hint_black_box;

const MAX_DNS_PACKET_SIZE: usize = 4096;

fn create_dns_query(query_id: u16, domain: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(512);

    // Header (12 bytes)
    packet.extend_from_slice(&query_id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00]); // Flags: standard query
    packet.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    packet.extend_from_slice(&[0x00, 0x00]); // Answer RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0

    // Question section
    for label in domain.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // Root label

    packet.extend_from_slice(&[0x00, 0x01]); // Type: A
    packet.extend_from_slice(&[0x00, 0x01]); // Class: IN

    packet
}

fn extract_query_id(buf: &[u8]) -> u16 {
    u16::from_be_bytes([buf[0], buf[1]])
}

fn validate_dns_packet(_buf: &[u8], len: usize) -> bool {
    len >= 12
}

fn bench_query_id_extraction(c: &mut Criterion) {
    let query = create_dns_query(0x1234, "example.com");

    c.bench_function("extract_query_id", |b| {
        b.iter(|| extract_query_id(black_box(&query)))
    });
}

fn bench_dns_packet_validation(c: &mut Criterion) {
    let query = create_dns_query(0x1234, "example.com");

    c.bench_function("validate_dns_packet", |b| {
        b.iter(|| validate_dns_packet(black_box(&query), query.len()))
    });
}

fn bench_pending_queries_insert(c: &mut Criterion) {
    let addr: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();

    c.bench_function("pending_queries_insert", |b| {
        let mut pending: HashMap<u16, std::net::SocketAddr> = HashMap::new();
        let mut id = 0u16;
        b.iter(|| {
            pending.insert(id, addr);
            id = id.wrapping_add(1);
            if id == 0 {
                pending.clear();
            }
        })
    });
}

fn bench_pending_queries_lookup_remove(c: &mut Criterion) {
    let addr: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let mut pending: HashMap<u16, std::net::SocketAddr> = HashMap::new();

    for i in 0..1000u16 {
        pending.insert(i, addr);
    }

    c.bench_function("pending_queries_lookup_remove", |b| {
        let mut id = 0u16;
        b.iter(|| {
            let _ = pending.remove(&id);
            pending.insert(id, addr);
            id = (id + 1) % 1000;
        })
    });
}

fn bench_buffer_allocation(c: &mut Criterion) {
    c.bench_function("buffer_allocation_stack", |b| {
        b.iter(|| {
            let buf: [u8; MAX_DNS_PACKET_SIZE] = [0u8; MAX_DNS_PACKET_SIZE];
            hint_black_box(buf);
        })
    });

    c.bench_function("buffer_allocation_vec", |b| {
        b.iter(|| {
            let buf = vec![0u8; MAX_DNS_PACKET_SIZE];
            hint_black_box(buf);
        })
    });
}

fn bench_dns_query_creation(c: &mut Criterion) {
    c.bench_function("create_dns_query_short", |b| {
        b.iter(|| create_dns_query(black_box(0x1234), black_box("example.com")))
    });

    c.bench_function("create_dns_query_long", |b| {
        b.iter(|| {
            create_dns_query(
                black_box(0x1234),
                black_box("subdomain.example.domain.com"),
            )
        })
    });
}

fn bench_packet_copy(c: &mut Criterion) {
    let query = create_dns_query(0x1234, "example.com");
    let mut buf = [0u8; MAX_DNS_PACKET_SIZE];

    c.bench_function("packet_copy_to_buffer", |b| {
        b.iter(|| {
            buf[..query.len()].copy_from_slice(black_box(&query));
            hint_black_box(&buf);
        })
    });
}

fn bench_throughput(c: &mut Criterion) {
    let queries: Vec<Vec<u8>> = (0..1000u16)
        .map(|id| create_dns_query(id, "example.com"))
        .collect();

    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Elements(1000));

    group.bench_function("process_1000_queries", |b| {
        b.iter(|| {
            let mut pending: HashMap<u16, std::net::SocketAddr> = HashMap::with_capacity(1000);
            let addr: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();

            for query in &queries {
                if validate_dns_packet(query, query.len()) {
                    let id = extract_query_id(query);
                    pending.insert(id, addr);
                }
            }

            for query in &queries {
                let id = extract_query_id(query);
                let _ = pending.remove(&id);
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_query_id_extraction,
    bench_dns_packet_validation,
    bench_pending_queries_insert,
    bench_pending_queries_lookup_remove,
    bench_buffer_allocation,
    bench_dns_query_creation,
    bench_packet_copy,
    bench_throughput,
);

criterion_main!(benches);
