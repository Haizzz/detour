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
        let domains = DOMAINS_LIST
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    return None;
                }
                Some(line.to_lowercase())
            })
            .collect();

        Self { domains }
    }

    /// Check if a domain should be blocked.
    ///
    /// Performs exact match and subdomain matching (e.g., blocks
    /// "ads.example.com" if "example.com" is in the blocklist).
    pub fn is_blocked(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        let mut current = domain.as_str();

        loop {
            if self.domains.contains(current) {
                return true;
            }
            match current.find('.') {
                Some(pos) => current = &current[pos + 1..],
                None => return false,
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_parses_domains() {
        let blocklist = Blocklist::new();

        assert!(blocklist.len() > 0);
    }

    #[test]
    fn is_blocked_exact_match() {
        let blocklist = Blocklist::new();

        assert!(blocklist.is_blocked("doubleclick.com"));
    }

    #[test]
    fn is_blocked_subdomain_match() {
        let blocklist = Blocklist::new();

        assert!(blocklist.is_blocked("ads.doubleclick.com"));
        assert!(blocklist.is_blocked("tracker.ads.doubleclick.com"));
    }

    #[test]
    fn is_blocked_case_insensitive() {
        let blocklist = Blocklist::new();

        assert!(blocklist.is_blocked("DOUBLECLICK.COM"));
        assert!(blocklist.is_blocked("ADS.doubleclick.com"));
    }

    #[test]
    fn is_blocked_returns_false_for_safe_domains() {
        let blocklist = Blocklist::new();

        assert!(!blocklist.is_blocked("google.com"));
        assert!(!blocklist.is_blocked("github.com"));
        assert!(!blocklist.is_blocked("example.org"));
    }

    #[test]
    fn is_blocked_handles_empty_input() {
        let blocklist = Blocklist::new();

        assert!(!blocklist.is_blocked(""));
    }
}
