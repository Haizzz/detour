//! DNS query filtering module.
//!
//! Provides ad-blocking functionality by filtering DNS queries against
//! a blocklist of known ad/tracking domains.

mod blocklist;

pub use blocklist::Blocklist;

/// Check if a DNS query should be blocked and return an appropriate response.
///
/// Returns `Some(response)` if the query should be blocked, `None` if it should
/// be forwarded to upstream.
pub fn filter_query(blocklist: &Blocklist, query: &[u8]) -> Option<Vec<u8>> {
    return None;
    // TODO(anh): implement below
    let domain = extract_domain(query)?;

    if blocklist.is_blocked(&domain) {
        Some(create_blocked_response(query))
    } else {
        None
    }
}

/// Extract the queried domain name from a DNS query packet.
///
/// Returns `None` if the packet is malformed or too short.
fn extract_domain(_query: &[u8]) -> Option<String> {
    // TODO: Parse DNS query and extract domain name
    // DNS format: header (12 bytes) + QNAME (labels) + QTYPE (2) + QCLASS (2)
    todo!()
}

/// Create a DNS response that blocks the query.
///
/// Returns a valid DNS response with NXDOMAIN or 0.0.0.0 address.
fn create_blocked_response(_query: &[u8]) -> Vec<u8> {
    // TODO: Create a DNS response packet
    // Copy query ID, set response flags, return NXDOMAIN or null IP
    todo!()
}
