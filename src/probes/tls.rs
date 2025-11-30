// src/probes/tls.rs
use super::Probe;
use crate::service::ServiceFingerprint;
use async_trait::async_trait;
use std::sync::Arc;
//use hyper::ext;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName};
use webpki_roots::TLS_SERVER_ROOTS;
use x509_parser::prelude::*;

pub struct TlsProbe;

#[async_trait]
impl Probe for TlsProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let addr = format!("{}:{}", ip, port);

        // Build root store
        let mut root_store = RootCertStore::empty();
        let roots = TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        });
        root_store.add_server_trust_anchors(roots);

        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));

        // Prefer using ip as SNI if it's a valid DNS name; otherwise fallback to "localhost"
        let server_name = match ServerName::try_from(ip) {
            Ok(s) => s,
            Err(_) => {
                if let Ok(s) = ServerName::try_from("localhost") { s } else { return None; }
            }
        };

        // TCP connect with timeout
        let tcp = match tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };

        // TLS handshake with timeout
        let tls_stream = match tokio::time::timeout(Duration::from_millis(timeout_ms), connector.connect(server_name, tcp)).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };

        // Extract peer certificates
        let certs_opt = tls_stream.get_ref().1.peer_certificates();
        let certs = match certs_opt {
            Some(c) if !c.is_empty() => c,
            _ => return None,
        };

        // Parse leaf certificate (DER)
        let der = &certs[0].0;
        if let Ok((_, parsed)) = x509_parser::parse_x509_certificate(der) {
            // CN (common name) best-effort
            let subject_cn = parsed.subject().iter_common_name().next()
                .and_then(|cn| cn.as_str().ok()).unwrap_or("").to_string();

            // SANs
            let mut sans = Vec::new();
            if let Ok(Some(ext)) = parsed.subject_alternative_name() {
                for name in ext.value.general_names.iter() {
                    if let GeneralName::DNSName(d) = name {
                        sans.push(d.to_string());
                    }
                }
            }

            let fp = ServiceFingerprint::from_tls_cert(ip, port, subject_cn, sans);
            return Some(fp);
        }

        None
    }

    fn ports(&self) -> Vec<u16> { vec![443, 8443, 9443] }
    fn name(&self) -> &'static str { "tls" }
}
