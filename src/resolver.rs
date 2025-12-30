//! DNS query resolution logic.
//!
//! Handles the core query processing pipeline:
//! 1. Filter (block ads/trackers)
//! 2. Cache lookup
//! 3. Decide whether to forward or return cached/blocked response
//!
//! Transports handle the actual I/O, resolver handles decisions.

use crate::cache::DnsCache;
use crate::dns::DnsQuery;
use crate::filter::{Blocklist, filter_query};
use crate::stats::{Stats, StatsSnapshot};

/// Action to take for a DNS query.
pub enum QueryAction {
    /// Query is blocked, return this response immediately.
    Blocked { response: Vec<u8>, domain: String },
    /// Query was found in cache, return this response immediately.
    Cached { response: Vec<u8>, domain: String },
    /// Query should be forwarded to upstream.
    Forward { domain: String },
    /// Query could not be parsed.
    Invalid,
}

/// Resolver handles DNS query processing decisions.
///
/// Contains all shared logic between transports: filtering, caching decisions,
/// upstream selection, etc. Transports call this to decide what to do with queries.
pub struct Resolver {
    blocklist: Blocklist,
    cache: DnsCache,
    stats: Stats,
}

impl Resolver {
    /// Create a new resolver with the given blocklist.
    pub fn new(blocklist: Blocklist) -> Self {
        Self {
            blocklist,
            cache: DnsCache::new(),
            stats: Stats::new(),
        }
    }

    /// Process a DNS query and decide what action to take.
    ///
    /// This is the main entry point for transports. Call this with the raw
    /// DNS query (without TCP length prefix) to get the action to take.
    pub fn process_query(&self, data: &[u8]) -> QueryAction {
        let Some(query) = DnsQuery::parse(data) else {
            return QueryAction::Invalid;
        };

        let domain = query.domain.clone();

        // Step 1: Check blocklist
        if let Some(blocked_response) = filter_query(&self.blocklist, &query) {
            return QueryAction::Blocked {
                response: blocked_response,
                domain,
            };
        }

        // Step 2: Check cache
        if let Some(cached_response) = self.cache.get(&query) {
            return QueryAction::Cached {
                response: cached_response,
                domain,
            };
        }

        // Step 3: Forward to upstream
        QueryAction::Forward { domain }
    }

    /// Called when we receive a response from upstream.
    ///
    /// Caches the response. Parses the question from the response itself
    /// (DNS responses include the question section).
    pub fn process_response(&self, response: &[u8]) {
        if let Some(query) = DnsQuery::parse(response) {
            self.cache.put(&query, response);
        }
    }

    /// Returns the number of domains in the blocklist.
    pub fn blocked_count(&self) -> usize {
        self.blocklist.len()
    }

    /// Returns the number of entries in the cache.
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Record a forwarded request with response time.
    pub fn record_forwarded(&self, response_time_ms: f64) {
        self.stats.record_forwarded(response_time_ms);
    }

    /// Record a cached response with response time.
    pub fn record_cached(&self, response_time_ms: f64) {
        self.stats.record_cached(response_time_ms);
    }

    /// Record a blocked request with response time.
    pub fn record_blocked(&self, response_time_ms: f64) {
        self.stats.record_blocked(response_time_ms);
    }

    /// Get a snapshot of current stats and reset counters.
    pub fn stats_snapshot_and_reset(&self) -> StatsSnapshot {
        self.stats.snapshot_and_reset()
    }
}
