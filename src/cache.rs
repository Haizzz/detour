//! DNS response cache with TTL-based expiration.

use rustc_hash::FxHashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::dns::{DnsQuery, DnsResponse};

struct CacheEntry {
    response: Vec<u8>,
    expires_at: Instant,
}

/// TTL-based DNS cache.
///
/// Uses a 2-level map (qtype -> domain -> entry) to avoid allocations on lookup.
pub struct DnsCache {
    entries: RwLock<FxHashMap<u16, FxHashMap<String, CacheEntry>>>,
    min_ttl: Duration,
    max_ttl: Duration,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(FxHashMap::default()),
            min_ttl: Duration::from_secs(60),
            max_ttl: Duration::from_secs(86400),
        }
    }

    /// Look up a cached response (no allocation on hit or miss).
    pub fn get(&self, query: &DnsQuery) -> Option<Vec<u8>> {
        let now = Instant::now();
        let domain = query.domain.as_str();

        {
            let Ok(entries) = self.entries.read() else {
                return None;
            };
            if let Some(inner) = entries.get(&query.qtype) {
                if let Some(entry) = inner.get(domain) {
                    if now < entry.expires_at {
                        return query.response_from_cache(&entry.response);
                    }
                }
            }
        }

        let Ok(mut entries) = self.entries.write() else {
            return None;
        };
        if let Some(inner) = entries.get_mut(&query.qtype) {
            if let Some(entry) = inner.get(domain) {
                if now >= entry.expires_at {
                    inner.remove(domain);
                }
            }
        }
        None
    }

    /// Store a response in the cache (allocates only on insert).
    pub fn put(&self, query: &DnsQuery, response: &[u8]) {
        let ttl = DnsResponse::parse_min_ttl(response, self.min_ttl);
        let ttl = ttl.clamp(self.min_ttl, self.max_ttl);

        let Ok(mut entries) = self.entries.write() else {
            return;
        };

        let inner = entries.entry(query.qtype).or_default();
        inner.insert(
            query.domain.clone(),
            CacheEntry {
                response: response.to_vec(),
                expires_at: Instant::now() + ttl,
            },
        );
    }

    pub fn len(&self) -> usize {
        self.entries
            .read()
            .map(|e| e.values().map(|inner| inner.len()).sum())
            .unwrap_or(0)
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}
