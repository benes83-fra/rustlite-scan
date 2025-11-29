use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct PortResult {
    pub port: u16,
    pub protocol: &'static str, // "tcp" or "udp"
    pub state: &'static str,    // "open", "closed", "filtered", "unknown"
    pub banner: Option<String>,
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

#[derive(Debug, Serialize, Clone)]
pub struct HostResult {
    pub host: String,
    pub ip: String,
    pub results: Vec<PortResult>,
    pub udp_metrics: Option<UdpMetrics>, // new field
}

