//! DNS query filtering module.
//!
//! Provides ad-blocking functionality by filtering DNS queries against
//! a blocklist of known ad/tracking domains.

mod blocklist;

pub use blocklist::Blocklist;

use crate::dns::DnsQuery;

/// Check if a DNS query should be blocked and return an appropriate response.
///
/// Returns `Some(response)` if the query should be blocked, `None` if it should
/// be forwarded to upstream.
pub fn filter_query(blocklist: &Blocklist, query: &DnsQuery) -> Option<Vec<u8>> {
    if blocklist.is_blocked(&query.domain) {
        Some(query.blocked_response().to_bytes())
    } else {
        None
    }
}
