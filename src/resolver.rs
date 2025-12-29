//! DNS query resolution logic.
//!
//! Handles the core query processing pipeline:
//! 1. Filter (block ads/trackers)
//! 2. Cache lookup (future)
//! 3. Decide whether to forward or return cached/blocked response
//!
//! Transports handle the actual I/O, resolver handles decisions.

use crate::filter::{Blocklist, filter_query, get_domain};

/// Action to take for a DNS query.
pub enum QueryAction {
    /// Query is blocked, return this response immediately.
    Blocked {
        response: Vec<u8>,
        domain: String,
    },
    /// Query should be forwarded to upstream.
    Forward {
        domain: String,
    },
    // Future: Cached(Vec<u8>), RaceUpstreams, etc.
}

/// Resolver handles DNS query processing decisions.
///
/// Contains all shared logic between transports: filtering, caching decisions,
/// upstream selection, etc. Transports call this to decide what to do with queries.
pub struct Resolver {
    blocklist: Blocklist,
    // Future: cache, multiple upstreams, retry policy, etc.
}

impl Resolver {
    /// Create a new resolver with the given blocklist.
    pub fn new(blocklist: Blocklist) -> Self {
        Self { blocklist }
    }

    /// Process a DNS query and decide what action to take.
    ///
    /// This is the main entry point for transports. Call this with the raw
    /// DNS query (without TCP length prefix) to get the action to take.
    pub fn process_query(&self, query: &[u8]) -> QueryAction {
        let domain = get_domain(query).unwrap_or_else(|| "<unknown>".to_string());

        // Step 1: Check blocklist
        if let Some(blocked_response) = filter_query(&self.blocklist, query) {
            return QueryAction::Blocked {
                response: blocked_response,
                domain,
            };
        }

        // Step 2: TODO - Check cache
        // if let Some(cached) = self.cache.get(query) {
        //     return QueryAction::Cached(cached);
        // }

        // Step 3: Forward to upstream
        QueryAction::Forward { domain }
    }

    /// Called when we receive a response from upstream.
    ///
    /// Used for caching, metrics, etc.
    pub fn process_response(&self, _query: &[u8], _response: &[u8]) {
        // TODO: Cache the response
        // TODO: Update metrics
    }

    /// Returns the number of domains in the blocklist.
    pub fn blocked_count(&self) -> usize {
        self.blocklist.len()
    }
}
