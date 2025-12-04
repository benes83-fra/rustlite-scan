pub mod tcp;
pub mod udp;
pub mod icmp;
pub mod http;
pub mod ssh;
pub mod tls;
pub mod ftp;
pub mod smtp;
pub mod dns;
pub use tcp::tcp_probe;
pub use udp::udp_probe;
pub use icmp::icmp_ping_addr;
pub use tls::TlsProbe;
use async_trait::async_trait;
use std::sync::Arc;
use crate::service::ServiceFingerprint;

#[async_trait]
pub trait Probe: Send + Sync {
    /// Probe the given ip:port with a timeout in ms. Return Some fingerprint on success.
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint>;
    /// Ports this probe targets; empty means "try on any open port"
    fn ports(&self) -> Vec<u16>;
    /// Human name for logging
    fn name(&self) -> &'static str { "generic" }
}

pub type ProbeHandle = Arc<dyn Probe>;

pub fn default_probes() -> Vec<ProbeHandle> {
    vec![
        Arc::new(crate::probes::http::HttpProbe {}),
        Arc::new(crate::probes::ssh::SshProbe {}),
        Arc::new(crate::probes::tls::TlsProbe {}),
        Arc::new(crate::probes::ftp::FtpProbe {}),
        Arc::new(crate::probes::smtp::SmtpProbe {}),
        Arc::new(crate::probes::dns::DnsProbe {}),
        // add more probes here
    ]
}

