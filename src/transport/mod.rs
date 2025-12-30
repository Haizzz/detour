//! Transport layer implementations for DNS proxy.
//!
//! Provides UDP and TCP transports for receiving DNS queries from clients
//! and forwarding them to upstream servers.

pub mod tcp;
pub mod udp;

/// Maximum size of a DNS packet (with some headroom).
pub const MAX_DNS_PACKET_SIZE: usize = 4096;

use std::net::SocketAddr;
use std::time::SystemTime;

/// Transport protocol identifier for logging.
#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
        }
    }
}

/// Logger for DNS query events.
pub struct QueryLogger {
    protocol: Protocol,
}

impl QueryLogger {
    pub fn new(protocol: Protocol) -> Self {
        Self { protocol }
    }

    pub fn blocked(&self, domain: &str, elapsed_ms: f64) {
        println!(
            "[{}] [{}] {} BLOCKED total={:.3}ms",
            timestamp(),
            self.protocol.as_str(),
            domain,
            elapsed_ms
        );
    }

    pub fn cached(&self, domain: &str, elapsed_ms: f64) {
        println!(
            "[{}] [{}] {} CACHED total={:.3}ms",
            timestamp(),
            self.protocol.as_str(),
            domain,
            elapsed_ms
        );
    }

    pub fn forwarded(&self, domain: &str, total_ms: f64, upstream_ms: f64, from: SocketAddr) {
        println!(
            "[{}] [{}] {} FORWARDED total={:.3}ms upstream={:.3}ms (from {})",
            timestamp(),
            self.protocol.as_str(),
            domain,
            total_ms,
            upstream_ms,
            from
        );
    }
}

fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = now.as_secs();
    
    // Days since epoch
    let days = total_secs / 86400;
    
    // Calculate year, month, day from days since 1970-01-01
    let (year, month, day) = days_to_ymd(days);
    
    // Time of day
    let day_secs = total_secs % 86400;
    let hours = day_secs / 3600;
    let mins = (day_secs % 3600) / 60;
    let secs = day_secs % 60;
    
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day, hours, mins, secs)
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Days since 1970-01-01
    let mut remaining = days as i64;
    let mut year = 1970i64;
    
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }
    
    let leap = is_leap_year(year);
    let days_in_months: [i64; 12] = [
        31, if leap { 29 } else { 28 }, 31, 30, 31, 30,
        31, 31, 30, 31, 30, 31
    ];
    
    let mut month = 1;
    for days_in_month in days_in_months {
        if remaining < days_in_month {
            break;
        }
        remaining -= days_in_month;
        month += 1;
    }
    
    (year as u64, month, remaining as u64 + 1)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}
