//! Benchmarks for blocklist domain lookup.
//!
//! Measures how quickly we can check if a domain is blocked.

use criterion::{black_box, BenchmarkId, Criterion, Throughput};

use detour::filter::Blocklist;

fn bench_is_blocked(c: &mut Criterion) {
    let blocklist = Blocklist::new();

    let mut group = c.benchmark_group("blocklist");

    // Benchmark exact match (blocked domain)
    group.throughput(Throughput::Elements(1));
    group.bench_function(BenchmarkId::new("is_blocked", "exact_match"), |b| {
        b.iter(|| blocklist.is_blocked(black_box("doubleclick.com")))
    });

    // Benchmark subdomain match (blocked via parent)
    group.bench_function(BenchmarkId::new("is_blocked", "subdomain_match"), |b| {
        b.iter(|| blocklist.is_blocked(black_box("ads.tracking.doubleclick.com")))
    });

    // Benchmark miss (not blocked)
    group.bench_function(BenchmarkId::new("is_blocked", "miss"), |b| {
        b.iter(|| blocklist.is_blocked(black_box("www.google.com")))
    });

    // Benchmark deep subdomain miss
    group.bench_function(BenchmarkId::new("is_blocked", "deep_miss"), |b| {
        b.iter(|| blocklist.is_blocked(black_box("a.b.c.d.e.f.example.org")))
    });

    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_is_blocked(&mut criterion);
    criterion.final_summary();
}
