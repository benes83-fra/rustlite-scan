use serde::Serialize;
use chrono::{Utc, DateTime};
use crate::service::ServiceFingerprint;
#[derive(Debug, Serialize, Clone)]
pub struct PortResult {
    pub port: u16,
    pub protocol: &'static str,
    pub state: &'static str,
    pub banner: Option<String>,

    // NEW — all optional, so nothing breaks
    pub ttl: Option<u8>,
    pub window_size: Option<u32>,
    pub mss: Option<u16>,
    pub df: Option<bool>,
}


#[derive(Debug, Serialize, Clone, Default)]
pub struct UdpMetrics {
    pub attempts: u64,
    pub retries: u64,
    pub timeouts: u64,
    pub successes: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
}

/// Small serializable struct describing a limiter's configured settings
#[derive(Debug, Serialize, Clone)]
pub struct LimiterInfo {
    pub pps: u64,
    pub burst: u64,
}

#[derive(Debug, Serialize, Clone)]
pub struct HostResult {
    pub host: String,
    pub ip: String,
    pub results: Vec<PortResult>,
    pub udp_metrics: Option<UdpMetrics>,

    /// Optional diagnostics: which limiters were applied for this host
    pub host_limiter: Option<LimiterInfo>,
    pub global_limiter: Option<LimiterInfo>,
    pub fingerprints: Vec<ServiceFingerprint>,
}


#[derive(Debug, Serialize)]
pub struct ProbeEvent {
    pub ts: DateTime<Utc>,
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub protocol: String, // "tcp" or "udp"
    pub outcome: String,  // "sent", "recv", "timeout", "retry", "open", "closed", "open|filtered", "unknown"
    pub duration_ms: Option<u64>,
    pub banner: Option<String>,

    // cumulative UDP metrics at this point (if UDP)
    pub udp_attempts: Option<u64>,
    pub udp_retries: Option<u64>,
    pub udp_timeouts: Option<u64>,
    pub udp_successes: Option<u64>,
    pub udp_packets_sent: Option<u64>,
    pub udp_packets_received: Option<u64>,

    // limiter metadata
    pub host_limiter_pps: Option<u64>,
    pub host_limiter_burst: Option<u64>,
    pub global_limiter_pps: Option<u64>,
    pub global_limiter_burst: Option<u64>,

    pub note: Option<String>,
}
