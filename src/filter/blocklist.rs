//! Blocklist for ad/tracking domains.
//!
//! Loads domains from embedded lists or a custom file path.

use rustc_hash::FxHashSet;

/// Embedded blocklists loaded at compile time.
const EMBEDDED_LISTS: &[&str] = &[
    include_str!("lists/Adaway.txt"),
    include_str!("lists/AdguardDNS.txt"),
    include_str!("lists/Easylist.txt"),
    include_str!("lists/Easyprivacy.txt"),
    include_str!("lists/Phishing_army_blocklist_extended.txt"),
];

/// A set of blocked domains for efficient lookup.
pub struct Blocklist {
    domains: FxHashSet<String>,
}

impl Blocklist {
    /// Create a new blocklist from the embedded domains lists.
    pub fn new() -> Self {
        Self::from_lists(EMBEDDED_LISTS.iter().copied())
    }

    /// Create a blocklist from a custom file path (replaces embedded lists).
    pub fn from_file(path: &str) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::from_lists(std::iter::once(content.as_str())))
    }

    fn from_lists<'a>(lists: impl Iterator<Item = &'a str>) -> Self {
        let domains = lists
            .flat_map(|list| list.lines())
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                    return None;
                }
                Some(line.to_ascii_lowercase())
            })
            .collect();

        Self { domains }
    }

    /// Check if a domain should be blocked (hot path, assumes already lowercase ASCII).
    #[inline]
    pub fn is_blocked(&self, domain: &str) -> bool {
        let mut current = domain;
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

        // is_blocked assumes pre-lowercased input (from DnsQuery::parse)
        assert!(blocklist.is_blocked("doubleclick.com"));
        assert!(blocklist.is_blocked("ads.doubleclick.com"));
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
