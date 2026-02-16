pub mod coap;
pub mod context;
pub mod dns;
pub mod elastic;
pub mod ftp;
pub mod helper;
pub mod http;
pub mod https;
pub mod icmp;
pub mod imap;
pub mod kafka;
pub mod ldap;
pub mod memcached;
pub mod modbus;
pub mod mongo;
pub mod mqtt;
pub mod mysql;
pub mod nbns;
pub mod nbns_helper;
pub mod ntp;
pub mod pop3;
pub mod postgres;
pub mod rabbitMQ;
pub mod radius;
pub mod rdp;
pub mod redis;
pub mod rtsp;
pub mod sip;
pub mod smb;
pub mod smtp;
pub mod snmp;
pub mod ssdp;
pub mod ssh;
pub mod tcp;
pub mod tcp_rst;
pub mod tcp_syn_helper;
pub mod tcps_syn;
pub mod tls;
pub mod tls_ja3;
pub mod udp;
pub mod vnc;
use crate::service::ServiceFingerprint;
use async_trait::async_trait;
pub use context::ProbeContext;
pub use icmp::icmp_ping_addr;
use std::sync::Arc;
pub use tcp::tcp_probe;
pub use udp::udp_probe;

#[async_trait]
pub trait Probe: Send + Sync {
    /// Probe the given ip:port with a timeout in ms. Return Some fingerprint on success.
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint>;
    /// Ports this probe targets; empty means "try on any open port"
    fn ports(&self) -> Vec<u16>;
    /// Human name for logging
    fn name(&self) -> &'static str {
        "generic"
    }
    async fn probe_with_ctx(
        &self,
        ip: &str,
        port: u16,
        ctx: ProbeContext,
    ) -> Option<ServiceFingerprint>;
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
        Arc::new(crate::probes::snmp::SnmpProbe {}),
        Arc::new(crate::probes::smb::SmbProbe {}),
        Arc::new(crate::probes::nbns::NbnsProbe {}),
        Arc::new(crate::probes::postgres::PostgresProbe {}),
        Arc::new(crate::probes::mysql::MysqlProbe {}),
        Arc::new(crate::probes::redis::RedisProbe {}),
        Arc::new(crate::probes::mongo::MongoProbe {}),
        Arc::new(crate::probes::elastic::ElasticProbe {}),
        Arc::new(crate::probes::rabbitMQ::RabbitMqProbe {}),
        Arc::new(crate::probes::kafka::KafkaProbe {}),
        Arc::new(crate::probes::ntp::NtpProbe {}),
        Arc::new(crate::probes::vnc::VncProbe {}),
        Arc::new(crate::probes::rtsp::RtspProbe {}),
        Arc::new(crate::probes::sip::SipProbe {}),
        Arc::new(crate::probes::ssdp::SsdpProbe {}),
        Arc::new(crate::probes::mqtt::MqttProbe {}),
        Arc::new(crate::probes::memcached::MemcachedProbe {}),
        Arc::new(crate::probes::modbus::ModbusProbe {}),
        Arc::new(crate::probes::radius::RadiusProbe {}),
        Arc::new(crate::probes::coap::CoapProbe {}),
        #[cfg(feature = "syn_fingerprint")]
        Arc::new(crate::probes::tcps_syn::TcpSynProbe {}),
        Arc::new(crate::probes::tcp_rst::TcpRstProbe {}), // add more probes here
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
