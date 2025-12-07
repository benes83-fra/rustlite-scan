use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt,AsyncWriteExt};
use std::time::Duration;
use openssl::ssl::{SslConnector, SslMethod};
use tokio_openssl::SslStream;

use crate::service::ServiceFingerprint;
use super::Probe;
use crate::probes::tls::fingerprint_tls;
use crate::probes::probe_helper::probe_exchange_tls;

pub struct LdapProbe;

#[async_trait::async_trait]
impl Probe for LdapProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        // Anonymous bind
        let bind_request: Vec<u8> = vec![
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07,
            0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
        ];

        let evidence = probe_exchange_tls(ip, port, timeout_ms, &bind_request, "ldap", decode_ldap_response, false).await?;

        // If StartTLS supported, send ExtendedRequest and upgrade
        let starttls_request: Vec<u8> = vec![
            0x30, 0x11, 0x02, 0x01, 0x02, 0x77, 0x0c, 0x80, 0x0b,
            // OID 1.3.6.1.4.1.1466.20037
            0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e,
            0x34, 0x2e, 0x31, 0x2e, 0x31, 0x34, 0x36, 0x36,
            0x2e, 0x32, 0x30, 0x30, 0x33, 0x37,
        ];

        let evidence_tls = probe_exchange_tls(ip, port, timeout_ms, &starttls_request, "ldap", decode_ldap_response, true).await;

        Some(ServiceFingerprint::from_banner(ip, port, "ldap", evidence_tls.unwrap_or(evidence)))
    }

    fn ports(&self) -> Vec<u16> { vec![389, 636] }
    fn name(&self) -> &'static str { "ldap" }
}

fn decode_ldap_response(data: &[u8]) -> String {
    if let Some(pos) = data.iter().position(|&b| b == 0x61) {
        let code = data.get(pos + 2).copied().unwrap_or(255);
        format!("LDAP_bind_response: result_code={}", code)
    } else if let Some(pos) = data.iter().position(|&b| b == 0x78) {
        "LDAP_extended_response (StartTLS)".to_string()
    } else {
        format!("LDAP_raw: {:02x?}", &data[..std::cmp::min(32, data.len())])
    }
}







