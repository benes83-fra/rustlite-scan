// src/probes/tls.rs
use async_trait::async_trait;
use crate::service::ServiceFingerprint;
use super::Probe;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::net::TcpStream;
use x509_parser::prelude::*;

pub struct TlsProbe;

#[async_trait]
impl Probe for TlsProbe {
    async fn probe(&self, ip: &str, port: u16, _timeout_ms: u64) -> Option<ServiceFingerprint> {
        let addr = format!("{}:{}", ip, port);

        // Build connector that accepts any cert
        let mut builder = SslConnector::builder(SslMethod::tls()).ok()?;
        builder.set_verify(SslVerifyMode::NONE);
        let connector = builder.build();

        // Connect by IP (no hostname needed)
        let stream = TcpStream::connect(&addr).ok()?;
        let ssl_stream = connector.connect(ip, stream).ok()?; // "ip" here is fine

        // Grab peer cert
        let cert = ssl_stream.ssl().peer_certificate()?;
        let der = cert.to_der().ok()?;

        // Parse with x509-parser
        let (_, parsed) = parse_x509_certificate(&der).ok()?;

        // Extract CN
        let subject_cn = parsed.subject().iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or("")
            .to_string();

        // Extract SANs
        let mut sans = Vec::new();
        if let Ok(Some(ext)) = parsed.subject_alternative_name() {
            for name in ext.value.general_names.iter() {
                if let GeneralName::DNSName(d) = name {
                    sans.push(d.to_string());
                }
            }
        }

        Some(ServiceFingerprint::from_tls_cert(ip, port, subject_cn, sans))
    }

    fn ports(&self) -> Vec<u16> {
        vec![443, 8443, 9443]
    }

    fn name(&self) -> &'static str {
        "tls"
    }
}
