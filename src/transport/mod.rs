//! Transport layer implementations for DNS proxy.
//!
//! Provides UDP and TCP transports for receiving DNS queries from clients
//! and forwarding them to upstream servers.

pub mod tcp;
pub mod udp;

/// Maximum size of a DNS packet (with some headroom).
pub const MAX_DNS_PACKET_SIZE: usize = 4096;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_dns_packet_size_is_reasonable() {
        assert!(MAX_DNS_PACKET_SIZE >= 512, "must support standard DNS size");
        assert!(MAX_DNS_PACKET_SIZE <= 65535, "must fit in UDP datagram");
    }
}
