//! Detour - A performance focused DNS proxy.
//!
//! A minimal, single-threaded DNS proxy that supports:
//! - UDP and TCP transports
//! - Response caching with TTL-based expiration
//! - Domain blocklist filtering
//! - Upstream racing (queries multiple servers, uses first response)
//!
//! # Architecture
//!
//! - [`transport`] - UDP and TCP network handlers
//! - [`resolver`] - Query processing logic (block/cache/forward decisions)
//! - [`cache`] - TTL-aware DNS response cache
//! - [`filter`] - Domain blocklist matching
//! - [`dns`] - DNS message parsing and construction

pub mod cache;
pub mod dns;
pub mod filter;
pub mod resolver;
pub mod transport;
