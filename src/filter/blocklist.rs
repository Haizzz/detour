//! Blocklist for ad/tracking domains.
//!
//! Loads a static list of domains at compile time and provides
//! efficient lookup for blocked domains.

use std::collections::HashSet;

/// Embedded blocklist of ad domains, loaded at compile time.
const DOMAINS_LIST: &str = include_str!("domains.txt");

/// A set of blocked domains for efficient lookup.
pub struct Blocklist {
    domains: HashSet<String>,
}

impl Blocklist {
    /// Create a new blocklist from the embedded domains list.
    pub fn new() -> Self {
        // TODO: Parse DOMAINS_LIST and populate HashSet
        // Handle comments (#), empty lines, wildcards (*.example.com)
        return Self {
            domains: HashSet::new(),
        };
    }

    /// Check if a domain should be blocked.
    ///
    /// Performs exact match and subdomain matching (e.g., blocks
    /// "ads.example.com" if "example.com" is in the blocklist).
    pub fn is_blocked(&self, _domain: &str) -> bool {
        // TODO: Check domain and parent domains against blocklist
        todo!()
    }

    /// Returns the number of domains in the blocklist.
    pub fn len(&self) -> usize {
        self.domains.len()
    }
}

impl Default for Blocklist {
    fn default() -> Self {
        Self::new()
    }
}
