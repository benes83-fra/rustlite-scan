pub mod tcp;
pub mod udp;
pub mod icmp;
pub mod http;
pub mod ssh;
pub mod tls;
pub mod ftp;
pub mod smtp;
pub mod dns;
pub mod https;
pub mod imap;
pub mod pop3;
pub mod rdp;
pub mod helper;
pub mod ldap;
pub mod snmp;
pub mod nbns;
pub mod smb;
pub mod mysql;
pub mod context;
pub mod postgres;
pub mod nbns_helper;
pub use tcp::tcp_probe;
pub use udp::udp_probe;
pub use icmp::icmp_ping_addr;
pub use context::ProbeContext;
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
    async fn probe_with_ctx(&self, ip: &str, port: u16, ctx: ProbeContext) -> Option<ServiceFingerprint>;
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
        Arc::new(crate::probes::https::HttpsProbe {}),
        Arc::new(crate::probes::imap::ImapProbe {}),
        Arc::new(crate::probes::pop3::Pop3Probe {}),
        Arc::new(crate::probes::rdp::RdpProbe {}),
        Arc::new(crate::probes::ldap::LdapProbe {}),
        Arc::new(crate::probes::snmp::SnmpProbe{}),
        Arc::new(crate::probes::smb::SmbProbe{}),
        Arc::new(crate::probes::nbns::NbnsProbe{}),
        Arc::new(crate::probes::postgres::PostgresProbe{}),
        Arc::new(crate::probes::mysql::MysqlProbe{}),
        // add more probes here
    ]
}

/// Normalized banner fields
#[derive(Debug, Clone)]
pub struct BannerFields {
    pub protocol: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub comment: Option<String>,
}

/// Trait for banner parsers
pub trait BannerParser {
    fn parse(raw: &str) -> BannerFields;
}
pub fn format_evidence(proto_name: &str, fields: BannerFields) -> String {
    let mut ev = String::new();
    if let Some(p) = fields.protocol {
        ev.push_str(&format!("{}_protocol: {}\n", proto_name.to_uppercase(), p));
    }
    if let Some(p) = fields.product {
        ev.push_str(&format!("{}_product: {}\n", proto_name.to_uppercase(), p));
    }
    if let Some(v) = fields.version {
        ev.push_str(&format!("{}_version: {}\n", proto_name.to_uppercase(), v));
    }
    if let Some(c) = fields.comment {
        ev.push_str(&format!("{}_comment: {}\n", proto_name.to_uppercase(), c));
    }
    ev
}
