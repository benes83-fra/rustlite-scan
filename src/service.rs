use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceFingerprint {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub protocol: String,         // e.g., "http", "https", "ssh"
    pub service: Option<String>,  // e.g., "nginx", "OpenSSH"
    pub version: Option<String>,  // e.g., "1.18.0"
    pub evidence: Option<String>, // raw banner, headers, cert subject, etc.
    pub evidence_type: Option<String>, // "banner", "http_header", "tls_cert"
    pub confidence: u8,          // 0..=100
    pub first_seen: DateTime<Utc>,
}

impl ServiceFingerprint {
    pub fn new(ip: &str, port: u16, protocol: &str) -> Self {
        Self {
            host: ip.to_string(),
            ip: ip.to_string(),
            port,
            protocol: protocol.to_string(),
            service: None,
            version: None,
            evidence: None,
            evidence_type: None,
            confidence: 0,
            first_seen: Utc::now(),
        }
    }

    pub fn from_banner(ip: &str, port: u16, proto: &str, banner: String) -> Self {
        let mut f = Self::new(ip, port, proto);
        f.evidence = Some(banner);
        f.evidence_type = Some("banner".to_string());
        f.confidence = 50;
        f
    }

    pub fn from_http(ip: &str, port: u16, server_header: Option<String>, status: Option<u16>) -> Self {
        let mut f = Self::new(ip, port, "http");
        f.service = server_header.clone();
        f.evidence = server_header.clone();
        f.evidence_type = Some("http_header".to_string());
        f.confidence = if server_header.is_some() { 70 } else { 40 };
        if let Some(s) = status { f.evidence = Some(format!("status: {}", s)); }
        f
    }

    pub fn from_tls_cert(ip: &str, port: u16, subject: String, sans: Vec<String>) -> Self {
        let mut f = Self::new(ip, port, "tls");
        let evidence = if sans.is_empty() { subject.clone() } else { format!("{}; SANs: {}", subject, sans.join(",")) };
        f.evidence = Some(evidence);
        f.evidence_type = Some("tls_cert".to_string());
        f.confidence = 75;
        f
    }

    /// Merge another fingerprint into self, increasing confidence when evidence agrees.
    pub fn merge(&mut self, other: ServiceFingerprint) {
        // If same protocol/port/ip, combine evidence and bump confidence
        if self.ip == other.ip && self.port == other.port {
            if self.service.is_none() && other.service.is_some() {
                self.service = other.service.clone();
            }
            if self.version.is_none() && other.version.is_some() {
                self.version = other.version.clone();
            }
            // Combine evidence strings (keep short)
            let mut pieces = Vec::new();
            if let Some(e) = &self.evidence { pieces.push(e.clone()); }
            if let Some(e) = &other.evidence { pieces.push(e.clone()); }
            self.evidence = Some(pieces.join(" | "));
            // Increase confidence conservatively
            let new_conf = (self.confidence as u16 + other.confidence as u16).saturating_sub(20);
            self.confidence = std::cmp::min(100, new_conf as u8);
        }
    }
}
/// Combine multiple fingerprints for the same host:port into a single fingerprint.
/// Strategy: start from the highest-confidence fingerprint, merge others, and normalize.
pub fn consolidate_fingerprints(mut fps: Vec<ServiceFingerprint>) -> Option<ServiceFingerprint> {
    if fps.is_empty() { return None; }
    // sort by confidence desc
    fps.sort_by_key(|f| std::cmp::Reverse(f.confidence));
    let mut base = fps.remove(0);
    for f in fps {
        base.merge(f);
    }
    // normalize confidence: clamp 10..100
    if base.confidence < 10 { base.confidence = 10; }
    Some(base)
}




/// Consolidate multiple fingerprints per port into one per port.
/// Keeps highest-confidence fingerprint as base and merges others.
pub fn consolidate_by_port(fps: Vec<ServiceFingerprint>) -> Vec<ServiceFingerprint> {
    let mut by_port: HashMap<u16, Vec<ServiceFingerprint>> = HashMap::new();
    for fp in fps {
        by_port.entry(fp.port).or_default().push(fp);
    }

    let mut consolidated = Vec::new();
    for (_port, mut list) in by_port {
        // sort by confidence desc
        list.sort_by_key(|f| std::cmp::Reverse(f.confidence));
        let mut base = list.remove(0);
        for other in list {
            base.merge(other);
        }
        // normalize confidence floor
        if base.confidence < 10 { base.confidence = 10; }
        consolidated.push(base);
    }
    consolidated
}

