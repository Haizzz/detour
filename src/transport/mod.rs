//! Transport layer implementations for DNS proxy.
//!
//! Provides UDP and TCP transports for receiving DNS queries from clients
//! and forwarding them to upstream servers.

pub mod tcp;
pub mod udp;

/// Maximum size of a DNS packet (with some headroom).
pub const MAX_DNS_PACKET_SIZE: usize = 4096;
