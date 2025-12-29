//! DNS query filtering module.
//!
//! Provides ad-blocking functionality by filtering DNS queries against
//! a blocklist of known ad/tracking domains.

mod blocklist;

pub use blocklist::Blocklist;

/// Extract the queried domain name from a DNS query packet.
///
/// Returns `None` if the packet is malformed or too short.
pub fn get_domain(query: &[u8]) -> Option<String> {
    extract_domain(query)
}

/// Check if a DNS query should be blocked and return an appropriate response.
///
/// Returns `Some(response)` if the query should be blocked, `None` if it should
/// be forwarded to upstream.
pub fn filter_query(blocklist: &Blocklist, query: &[u8]) -> Option<Vec<u8>> {
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
fn extract_domain(query: &[u8]) -> Option<String> {
    const HEADER_LEN: usize = 12;
    if query.len() < HEADER_LEN + 1 {
        return None;
    }

    let mut pos = HEADER_LEN;
    let mut domain_parts = Vec::new();

    loop {
        if pos >= query.len() {
            return None;
        }

        let label_len = query[pos] as usize;
        if label_len == 0 {
            break;
        }

        pos += 1;
        if pos + label_len > query.len() {
            return None;
        }

        let label = std::str::from_utf8(&query[pos..pos + label_len]).ok()?;
        domain_parts.push(label.to_string());
        pos += label_len;
    }

    if domain_parts.is_empty() {
        return None;
    }

    Some(domain_parts.join("."))
}

/// Create a DNS response that blocks the query.
///
/// Returns a valid DNS response with 0.0.0.0 as the answer.
fn create_blocked_response(query: &[u8]) -> Vec<u8> {
    let mut response = Vec::with_capacity(query.len() + 16);

    // Copy transaction ID from query
    response.extend_from_slice(&query[0..2]);

    // Flags: standard response, recursion available, no error
    // 0x8180 = response (1), opcode (0000), AA (0), TC (0), RD (1), RA (1), Z (000), RCODE (0000)
    response.extend_from_slice(&[0x81, 0x80]);

    // QDCOUNT: 1 question
    response.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT: 1 answer
    response.extend_from_slice(&[0x00, 0x01]);
    // NSCOUNT: 0
    response.extend_from_slice(&[0x00, 0x00]);
    // ARCOUNT: 0
    response.extend_from_slice(&[0x00, 0x00]);

    // Copy the question section from query (QNAME + QTYPE + QCLASS)
    let qname_start = 12;
    let mut pos = qname_start;
    while pos < query.len() && query[pos] != 0 {
        pos += 1 + query[pos] as usize;
    }
    pos += 1; // null terminator
    pos += 4; // QTYPE (2) + QCLASS (2)

    if pos <= query.len() {
        response.extend_from_slice(&query[qname_start..pos]);
    }

    // Answer section: pointer to QNAME + TYPE A + CLASS IN + TTL + RDLENGTH + 0.0.0.0
    // Name pointer to offset 12 (0xC00C)
    response.extend_from_slice(&[0xC0, 0x0C]);
    // TYPE: A (1)
    response.extend_from_slice(&[0x00, 0x01]);
    // CLASS: IN (1)
    response.extend_from_slice(&[0x00, 0x01]);
    // TTL: 300 seconds
    response.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
    // RDLENGTH: 4 bytes
    response.extend_from_slice(&[0x00, 0x04]);
    // RDATA: 0.0.0.0
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    response
}
