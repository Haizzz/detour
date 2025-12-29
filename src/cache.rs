//! DNS response cache with TTL-based expiration.

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::dns::{DnsQuery, DnsResponse};

/// A cached DNS response with expiration time.
struct CacheEntry {
    response: Vec<u8>,
    expires_at: Instant,
}

/// TTL-based DNS cache.
///
/// Caches responses keyed by (domain, query_type) with automatic expiration.
pub struct DnsCache {
    entries: RefCell<HashMap<CacheKey, CacheEntry>>,
    min_ttl: Duration,
    max_ttl: Duration,
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct CacheKey {
    domain: String,
    qtype: u16,
}

impl DnsCache {
    /// Create a new cache with default TTL bounds.
    pub fn new() -> Self {
        Self {
            entries: RefCell::new(HashMap::new()),
            min_ttl: Duration::from_secs(60),
            max_ttl: Duration::from_secs(86400),
        }
    }

    /// Look up a cached response for the given query.
    ///
    /// Returns the cached response with the query ID replaced to match the incoming query.
    pub fn get(&self, query: &DnsQuery) -> Option<Vec<u8>> {
        let key = CacheKey {
            domain: query.domain.clone(),
            qtype: query.qtype,
        };
        let mut entries = self.entries.borrow_mut();

        if let Some(entry) = entries.get(&key) {
            if Instant::now() < entry.expires_at {
                return query.response_from_cache(&entry.response);
            } else {
                entries.remove(&key);
            }
        }
        None
    }

    /// Store a response in the cache.
    ///
    /// Extracts TTL from the response and caches with appropriate expiration.
    pub fn put(&self, query: &DnsQuery, response: &[u8]) {
        let key = CacheKey {
            domain: query.domain.clone(),
            qtype: query.qtype,
        };

        let ttl = DnsResponse::parse_min_ttl(response, self.min_ttl);
        let ttl = ttl.clamp(self.min_ttl, self.max_ttl);

        self.entries.borrow_mut().insert(
            key,
            CacheEntry {
                response: response.to_vec(),
                expires_at: Instant::now() + ttl,
            },
        );
    }
}
