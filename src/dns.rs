//! DNS message parsing and construction.

use std::time::Duration;

const HEADER_LEN: usize = 12;

/// A parsed DNS query.
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub id: u16,
    pub domain: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl DnsQuery {
    /// Parse a DNS query from raw bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < HEADER_LEN + 1 {
            return None;
        }

        let id = u16::from_be_bytes([data[0], data[1]]);

        // Parse domain name
        let mut pos = HEADER_LEN;
        let mut domain_parts = Vec::new();

        while pos < data.len() {
            let label_len = data[pos] as usize;
            if label_len == 0 {
                pos += 1;
                break;
            }
            pos += 1;
            if pos + label_len > data.len() {
                return None;
            }
            let label = std::str::from_utf8(&data[pos..pos + label_len]).ok()?;
            domain_parts.push(label.to_string());
            pos += label_len;
        }

        if domain_parts.is_empty() {
            return None;
        }

        // Parse QTYPE and QCLASS
        if pos + 4 > data.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let qclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);

        Some(Self {
            id,
            domain: domain_parts.join(".").to_lowercase(),
            qtype,
            qclass,
        })
    }

    /// Create a blocked response (returns 0.0.0.0).
    pub fn blocked_response(&self) -> DnsResponse {
        DnsResponse::blocked(self)
    }

    /// Create a response from cached data, updating the transaction ID.
    pub fn response_from_cache(&self, cached: &[u8]) -> Option<Vec<u8>> {
        if cached.len() < 2 {
            return None;
        }
        let mut response = cached.to_vec();
        response[0] = (self.id >> 8) as u8;
        response[1] = (self.id & 0xFF) as u8;
        Some(response)
    }
}

/// A DNS response.
#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
}

/// A DNS question section entry.
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub domain: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// A DNS resource record.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl DnsResponse {
    /// Create a blocked response (0.0.0.0) for a query.
    pub fn blocked(query: &DnsQuery) -> Self {
        Self {
            id: query.id,
            flags: 0x8180, // Standard response, recursion available, no error
            questions: vec![DnsQuestion {
                domain: query.domain.clone(),
                qtype: query.qtype,
                qclass: query.qclass,
            }],
            answers: vec![DnsRecord {
                name: query.domain.clone(),
                rtype: 1, // A record
                class: 1, // IN
                ttl: 300,
                rdata: vec![0, 0, 0, 0], // 0.0.0.0
            }],
        }
    }

    /// Encode the response to wire format bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(512);

        // Header
        data.extend_from_slice(&self.id.to_be_bytes());
        data.extend_from_slice(&self.flags.to_be_bytes());
        data.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        data.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        data.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        data.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        // Questions
        for q in &self.questions {
            Self::encode_domain(&mut data, &q.domain);
            data.extend_from_slice(&q.qtype.to_be_bytes());
            data.extend_from_slice(&q.qclass.to_be_bytes());
        }

        // Answers
        for a in &self.answers {
            // Use compression pointer if this is the first question's domain
            if !self.questions.is_empty() && a.name == self.questions[0].domain {
                data.extend_from_slice(&[0xC0, 0x0C]); // Pointer to offset 12
            } else {
                Self::encode_domain(&mut data, &a.name);
            }
            data.extend_from_slice(&a.rtype.to_be_bytes());
            data.extend_from_slice(&a.class.to_be_bytes());
            data.extend_from_slice(&a.ttl.to_be_bytes());
            data.extend_from_slice(&(a.rdata.len() as u16).to_be_bytes());
            data.extend_from_slice(&a.rdata);
        }

        data
    }

    fn encode_domain(buf: &mut Vec<u8>, domain: &str) {
        for label in domain.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
    }

    /// Parse TTL from a response, returning the minimum TTL across all records.
    pub fn parse_min_ttl(response: &[u8], default: Duration) -> Duration {
        if response.len() < HEADER_LEN {
            return default;
        }

        let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
        let nscount = u16::from_be_bytes([response[8], response[9]]) as usize;
        let arcount = u16::from_be_bytes([response[10], response[11]]) as usize;
        let total_rrs = ancount + nscount + arcount;

        if total_rrs == 0 {
            return default;
        }

        let mut pos = HEADER_LEN;

        // Skip question section
        while pos < response.len() {
            let label_len = response[pos] as usize;
            if label_len == 0 {
                pos += 1;
                break;
            }
            if label_len >= 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + label_len;
        }
        pos += 4; // QTYPE + QCLASS

        let mut min_ttl = u32::MAX;

        for _ in 0..total_rrs {
            if pos >= response.len() {
                break;
            }

            // Skip name (handle compression)
            while pos < response.len() {
                let b = response[pos];
                if b == 0 {
                    pos += 1;
                    break;
                }
                if b >= 0xC0 {
                    pos += 2;
                    break;
                }
                pos += 1 + b as usize;
            }

            if pos + 10 > response.len() {
                break;
            }

            let ttl = u32::from_be_bytes([
                response[pos + 4],
                response[pos + 5],
                response[pos + 6],
                response[pos + 7],
            ]);
            min_ttl = min_ttl.min(ttl);

            let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
            pos += 10 + rdlength;
        }

        if min_ttl == u32::MAX {
            default
        } else {
            Duration::from_secs(min_ttl as u64)
        }
    }
}
