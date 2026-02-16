use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{format_evidence, BannerFields, BannerParser, Probe};
use crate::probes::ProbeContext;
use crate::service::ServiceFingerprint;
use openssl::ssl::{SslConnector, SslMethod};
use tokio_openssl::SslStream;

// Parser for POP3 greeting
pub struct Pop3BannerParser;

impl BannerParser for Pop3BannerParser {
    fn parse(raw: &str) -> BannerFields {
        let trimmed = raw.trim();
        let mut fields = BannerFields {
            protocol: Some("POP3".to_string()),
            product: None,
            version: None,
            comment: None,
        };

        // Typical greeting: "+OK Dovecot ready."
        if trimmed.starts_with("+OK") {
            let rest = trimmed.trim_start_matches("+OK").trim();
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
pub struct Pop3Probe;

#[async_trait]
impl Probe for Pop3Probe {
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
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let addr = format!("{}:{}", ip, port);

        // TCP connect with timeout
        let stream = match tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return None,
        };

        // Implicit TLS (POP3S) on 995
        if port == 995 {
            let tls_stream = upgrade_to_tls(stream, ip).await.ok()?;
            return fingerprint_pop3_tls(ip, port, tls_stream).await;
        }

        // Plain POP3 (110)
        let mut stream = stream;

        // Greeting banner
        let banner = read_chunk(&mut stream).await?;
        let fields = Pop3BannerParser::parse(&banner);
        let mut evidence = format_evidence("pop3", fields);

        // CAPA
        stream.write_all(b"CAPA\r\n").await.ok()?;
        if let Some(cap) = read_chunk(&mut stream).await {
            evidence.push_str(&format!("POP3_capability: {}\n", cap.trim()));
        }

        // STARTTLS negotiation
        if evidence.contains("STLS") {
            stream.write_all(b"STLS\r\n").await.ok()?;
            if let Some(reply) = read_chunk(&mut stream).await {
                evidence.push_str(&format!("POP3_starttls_reply: {}\n", reply.trim()));
                if reply.starts_with("+OK") {
                    if let Ok(tls_stream) = upgrade_to_tls(stream, ip).await {
                        return fingerprint_pop3_tls_with_evidence(ip, port, tls_stream, evidence)
                            .await;
                    }
                }
            }
        }

        Some(ServiceFingerprint::from_banner(ip, port, "pop3", evidence))
    }

    fn ports(&self) -> Vec<u16> {
        vec![110, 995]
    }
    fn name(&self) -> &'static str {
        "pop3"
    }
}

// TLS upgrade helper
async fn upgrade_to_tls(stream: TcpStream, sni: &str) -> Result<SslStream<TcpStream>, ()> {
    let connector = SslConnector::builder(SslMethod::tls())
        .map_err(|_| ())?
        .build();
    let ssl = connector
        .configure()
        .map_err(|_| ())?
        .into_ssl(sni)
        .map_err(|_| ())?;
    let mut tls = SslStream::new(ssl, stream).map_err(|_| ())?;
    let mut pinned = std::pin::Pin::new(&mut tls);
    pinned.as_mut().connect().await.map_err(|_| ())?;
    Ok(tls)
}

// Evidence collection after TLS upgrade
async fn fingerprint_pop3_tls(
    ip: &str,
    port: u16,
    mut tls_stream: SslStream<TcpStream>,
) -> Option<ServiceFingerprint> {
    let mut evidence = String::new();
    if let Some(banner) = read_chunk_tls(&mut tls_stream).await {
        let fields = Pop3BannerParser::parse(&banner);
        evidence.push_str(&format_evidence("pop3", fields));
    }
    tls_stream.write_all(b"CAPA\r\n").await.ok()?;
    if let Some(cap) = read_chunk_tls(&mut tls_stream).await {
        evidence.push_str(&format!("POP3_capability: {}\n", cap.trim()));
    }
    Some(ServiceFingerprint::from_banner(ip, port, "pop3", evidence))
}

async fn fingerprint_pop3_tls_with_evidence(
    ip: &str,
    port: u16,
    mut tls_stream: SslStream<TcpStream>,
    mut evidence: String,
) -> Option<ServiceFingerprint> {
    if let Some(banner) = read_chunk_tls(&mut tls_stream).await {
        let fields = Pop3BannerParser::parse(&banner);
        evidence.push_str(&format_evidence("pop3", fields));
    }
    tls_stream.write_all(b"CAPA\r\n").await.ok()?;
    if let Some(cap) = read_chunk_tls(&mut tls_stream).await {
        evidence.push_str(&format!("POP3_capability: {}\n", cap.trim()));
    }
    Some(ServiceFingerprint::from_banner(ip, port, "pop3", evidence))
}

// Simple readers
async fn read_chunk(stream: &mut TcpStream) -> Option<String> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await.ok()?;
    if n == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n]).to_string())
}

async fn read_chunk_tls(stream: &mut SslStream<TcpStream>) -> Option<String> {
    let mut buf = [0u8; 4096];
    let n = match tokio::time::timeout(Duration::from_millis(200), stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return None,
    };
    if n == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n]).to_string())
}
