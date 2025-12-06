use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;

use crate::service::ServiceFingerprint;
use super::{Probe, BannerFields, BannerParser, format_evidence};
use openssl::ssl::{SslConnector, SslMethod};
use tokio_openssl::SslStream;

pub struct ImapBannerParser;

impl BannerParser for ImapBannerParser {
    fn parse(raw: &str) -> BannerFields {
        let trimmed = raw.trim();
        let mut fields = BannerFields {
            protocol: Some("IMAP".to_string()),
            product: None,
            version: None,
            comment: None,
        };

        if trimmed.starts_with("* OK") {
            // Remove the leading "* OK"
            let rest = trimmed.trim_start_matches("* OK").trim();

            // If there's a capability block, strip it out
            let rest = if rest.starts_with("[CAPABILITY") {
                // find closing bracket
                if let Some(idx) = rest.find(']') {
                    rest[idx+1..].trim()
                } else {
                    rest
                }
            } else {
                rest
            };

            // Now split remaining words
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if !parts.is_empty() {
                fields.product = Some(parts[0].to_string());
            }
            if parts.len() > 1 {
                fields.version = Some(parts[1..].join(" "));
            }
        }
        fields
    }
}


pub struct ImapProbe;

#[async_trait]
impl Probe for ImapProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let addr = format!("{}:{}", ip, port);

        // TCP connect with timeout
        let stream = match tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            TcpStream::connect(&addr),
        ).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };

        // Implicit TLS (IMAPS) on 993
        if port == 993 {
            let tls_stream = upgrade_to_tls(stream, ip).await.ok()?;
            return fingerprint_imap_tls(ip, port, tls_stream).await;
        }

        // Plain IMAP (143)
        let mut stream = stream;

        // Greeting banner
        let banner = read_chunk(&mut stream).await?;
        let fields = ImapBannerParser::parse(&banner);
        let mut evidence = format_evidence("imap", fields);

        // CAPABILITY
        stream.write_all(b"0001 CAPABILITY\r\n").await.ok()?;
        if let Some(cap) = read_chunk(&mut stream).await {
            evidence.push_str(&format!("IMAP_capability: {}\n", cap.trim()));
        }

        // STARTTLS negotiation
        if evidence.contains("STARTTLS") {
            stream.write_all(b"0002 STARTTLS\r\n").await.ok()?;
            if let Some(reply) = read_chunk(&mut stream).await {
                evidence.push_str(&format!("IMAP_starttls_reply: {}\n", reply.trim()));
                if reply.contains("OK") {
                    if let Ok(tls_stream) = upgrade_to_tls(stream, ip).await {
                        return fingerprint_imap_tls_with_evidence(ip, port, tls_stream, evidence).await;
                    }
                }
            }
        }

        Some(ServiceFingerprint::from_banner(ip, port, "imap", evidence))
    }

    fn ports(&self) -> Vec<u16> { vec![143, 993] }
    fn name(&self) -> &'static str { "imap" }
}

// Parser for IMAP greeting

// TLS upgrade helper
async fn upgrade_to_tls(stream: TcpStream, sni: &str) -> Result<SslStream<TcpStream>, ()> {
    let connector = SslConnector::builder(SslMethod::tls()).map_err(|_| ())?.build();
    let ssl = connector.configure().map_err(|_| ())?.into_ssl(sni).map_err(|_| ())?;
    let mut tls = SslStream::new(ssl, stream).map_err(|_| ())?;
    let mut pinned = std::pin::Pin::new(&mut tls);
    pinned.as_mut().connect().await.map_err(|_| ())?;
    Ok(tls)
}

// Evidence collection after TLS upgrade
async fn fingerprint_imap_tls(ip: &str, port: u16, mut tls_stream: SslStream<TcpStream>) -> Option<ServiceFingerprint> {
    let mut evidence = String::new();
    if let Some(banner) = read_chunk_tls(&mut tls_stream).await {
        let fields = ImapBannerParser::parse(&banner);
        evidence.push_str(&format_evidence("imap", fields));
    }
    tls_stream.write_all(b"0001 CAPABILITY\r\n").await.ok()?;
    if let Some(cap) = read_chunk_tls(&mut tls_stream).await {
        evidence.push_str(&format!("IMAP_capability: {}\n", cap.trim()));
    }
    Some(ServiceFingerprint::from_banner(ip, port, "imap", evidence))
}

async fn fingerprint_imap_tls_with_evidence(
    ip: &str,
    port: u16,
    mut tls_stream: SslStream<TcpStream>,
    mut evidence: String,
) -> Option<ServiceFingerprint> {
    if let Some(banner) = read_chunk_tls(&mut tls_stream).await {
        let fields = ImapBannerParser::parse(&banner);
        evidence.push_str(&format_evidence("imap", fields));
    }
    tls_stream.write_all(b"0003 CAPABILITY\r\n").await.ok()?;
    if let Some(cap) = read_chunk_tls(&mut tls_stream).await {
        evidence.push_str(&format!("IMAP_capability: {}\n", cap.trim()));
    }
    Some(ServiceFingerprint::from_banner(ip, port, "imap", evidence))
}

// Simple readers
async fn read_chunk(stream: &mut TcpStream) -> Option<String> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await.ok()?;
    if n == 0 { return None; }
    Some(String::from_utf8_lossy(&buf[..n]).to_string())
}

async fn read_chunk_tls(stream: &mut SslStream<TcpStream>) -> Option<String> {
    let mut buf = [0u8; 4096];
    let n = match tokio::time::timeout(Duration::from_millis(200), stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return None,
    };
    if n == 0 { return None; }
    Some(String::from_utf8_lossy(&buf[..n]).to_string())
}
