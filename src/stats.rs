//! Statistics tracking for DNS proxy.

use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic statistics for tracking proxy performance.
pub struct Stats {
    pub requests: AtomicU64,
    pub forwarded: AtomicU64,
    pub cached: AtomicU64,
    pub blocked: AtomicU64,
    /// Cumulative response time in microseconds for averaging.
    total_response_time_us: AtomicU64,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            requests: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            cached: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            total_response_time_us: AtomicU64::new(0),
        }
    }

    pub fn record_forwarded(&self, response_time_ms: f64) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.forwarded.fetch_add(1, Ordering::Relaxed);
        self.total_response_time_us
            .fetch_add((response_time_ms * 1000.0) as u64, Ordering::Relaxed);
    }

    pub fn record_cached(&self, response_time_ms: f64) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.cached.fetch_add(1, Ordering::Relaxed);
        self.total_response_time_us
            .fetch_add((response_time_ms * 1000.0) as u64, Ordering::Relaxed);
    }

    pub fn record_blocked(&self, response_time_ms: f64) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.blocked.fetch_add(1, Ordering::Relaxed);
        self.total_response_time_us
            .fetch_add((response_time_ms * 1000.0) as u64, Ordering::Relaxed);
    }

    pub fn snapshot_and_reset(&self) -> StatsSnapshot {
        let requests = self.requests.swap(0, Ordering::Relaxed);
        let forwarded = self.forwarded.swap(0, Ordering::Relaxed);
        let cached = self.cached.swap(0, Ordering::Relaxed);
        let blocked = self.blocked.swap(0, Ordering::Relaxed);
        let total_us = self.total_response_time_us.swap(0, Ordering::Relaxed);

        let avg_response_ms = if requests > 0 {
            (total_us as f64 / requests as f64) / 1000.0
        } else {
            0.0
        };

        StatsSnapshot {
            requests,
            forwarded,
            cached,
            blocked,
            avg_response_ms,
        }
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

pub struct StatsSnapshot {
    pub requests: u64,
    pub forwarded: u64,
    pub cached: u64,
    pub blocked: u64,
    pub avg_response_ms: f64,
}
