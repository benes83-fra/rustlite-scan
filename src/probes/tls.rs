// src/probes/tls.rs
use crate::probes::ProbeContext;
use crate::service::ServiceFingerprint;
use async_trait::async_trait;

use super::Probe;
use openssl::nid::Nid;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509Ref;
use std::net::TcpStream;
use tokio_openssl::SslStream;
use x509_parser::prelude::*;

pub struct TlsProbe;

#[async_trait]
impl Probe for TlsProbe {
    async fn probe_with_ctx(
        &self,
        ip: &str,
        port: u16,
        ctx: ProbeContext,
    ) -> Option<ServiceFingerprint> {
        let timeout_ms = ctx
            .get("timeout_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(2000);
        self.probe(ip, port, timeout_ms).await
    }
    async fn probe(&self, ip: &str, port: u16, _timeout_ms: u64) -> Option<ServiceFingerprint> {
        let addr = format!("{}:{}", ip, port);

        // Build connector that accepts any cert
        let mut builder = SslConnector::builder(SslMethod::tls()).ok()?;
        builder.set_verify(SslVerifyMode::NONE);
        let connector = builder.build();

        // Connect by IP (no hostname needed)
        let stream = TcpStream::connect(&addr).ok()?;
        let ssl_stream = connector.connect(ip, stream).ok()?; // "ip" here is fine

        let ssl = ssl_stream.ssl();

        // NEW: TLS negotiation fingerprint
        let (neg_str, ja3s_like) = crate::probes::tls_ja3::build_tls_server_fingerprint(ssl);

        let mut evidence = String::new();
        evidence.push_str(&format!("tls_negotiation: {}\n", neg_str));
        evidence.push_str(&format!("tls_ja3s_like: {}\n", ja3s_like));

        // Grab peer cert
        let cert = ssl_stream.ssl().peer_certificate()?;
        let der = cert.to_der().ok()?;

        // Parse with x509-parser
        let (_, parsed) = parse_x509_certificate(&der).ok()?;

        // Extract CN
        let subject_cn = parsed
            .subject()
            .iter_common_name()
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

        // Preserve your existing SAN + CN logic
        let mut fp = ServiceFingerprint::from_tls_cert(ip, port, subject_cn, sans);

        // Append our new evidence to the existing evidence
        if let Some(old) = fp.evidence.take() {
            fp.evidence = Some(format!("{}\n{}", evidence, old));
        } else {
            fp.evidence = Some(evidence);
        }

        Some(fp)
    }

    fn ports(&self) -> Vec<u16> {
        vec![443, 8443, 9443]
    }

    fn name(&self) -> &'static str {
        "tls"
    }
}

pub async fn fingerprint_tls(
    ip: &str,
    port: u16,
    proto_name: &str,
    negotiation_info: String,
    tls_stream: SslStream<tokio::net::TcpStream>,
) -> Option<ServiceFingerprint> {
    let mut evidence = String::new();
    evidence.push_str(&negotiation_info);
    evidence.push('\n');

    // Extract peer certificate
    if let Some(cert) = tls_stream.ssl().peer_certificate() {
        // println!("Got peer certificate");
        push_cert_info(&mut evidence, cert.as_ref());
    } else {
        println!("No peer certificate presented");
    }
    // Extract full chain
    if let Some(chain) = tls_stream.ssl().peer_cert_chain() {
        //println!("Chain length: {}", chain.len());
        for (i, cert) in chain.iter().enumerate() {
            //println!("Chain cert {} subject: {:?}", i, cert_ref.subject_name());
            push_cert_info(&mut evidence, cert);

            evidence.push_str(&format!("TLS_chain_index: {}\n", i));
        }
    }

    Some(ServiceFingerprint::from_banner(
        ip, port, proto_name, evidence,
    ))
}
fn push_cert_info(out: &mut String, cert: &X509Ref) {
    // Subject CN
    if let Some(entry) = cert.subject_name().entries_by_nid(Nid::COMMONNAME).next() {
        if let Ok(cn) = entry.data().as_utf8() {
            out.push_str(&format!("TLS_cert_subject_cn: {}\n", cn));
        }
    }

    // Issuer CN
    if let Some(entry) = cert.issuer_name().entries_by_nid(Nid::COMMONNAME).next() {
        if let Ok(cn) = entry.data().as_utf8() {
            out.push_str(&format!("TLS_cert_issuer_cn: {}\n", cn));
        }
    }

    // Subject Alternative Names
    if let Some(sans) = cert.subject_alt_names() {
        for san in sans {
            if let Some(dns) = san.dnsname() {
                out.push_str(&format!("TLS_cert_san_dns: {}\n", dns));
            }
            if let Some(ip) = san.ipaddress() {
                // ipaddress() returns raw bytes
                if ip.len() == 4 {
                    out.push_str(&format!(
                        "TLS_cert_san_ip: {}.{}.{}.{}\n",
                        ip[0], ip[1], ip[2], ip[3]
                    ));
                } else {
                    out.push_str(&format!("TLS_cert_san_ip_hex: {:02x?}\n", ip));
                }
            }
        }
    }
}
