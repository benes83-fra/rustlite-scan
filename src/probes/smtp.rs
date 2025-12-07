use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;

use crate::service::ServiceFingerprint;
use super::Probe;
use openssl::ssl::{SslConnector, SslMethod};
use tokio_openssl::SslStream;



use super::{BannerFields, BannerParser, format_evidence};

pub struct SmtpBannerParser;

impl BannerParser for SmtpBannerParser {
    fn parse(raw: &str) -> BannerFields {
        let trimmed = raw.trim();
        let mut fields = BannerFields {
            protocol: None,
            product: None,
            version: None,
            comment: None,
        };

        // Typical banner: "220 mail.example.com ESMTP Postfix"
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == "220" {
            fields.protocol = Some("SMTP".to_string());
            // host is parts[1]
            fields.comment = Some(parts[1].to_string());
            // product/version often appear later
            if parts.len() >= 3 {
                fields.product = Some(parts[2].to_string());
            }
            if parts.len() >= 4 {
                fields.version = Some(parts[3..].join(" "));
            }
        }
        fields
    }
}
pub struct SmtpProbe;

#[async_trait]
impl Probe for SmtpProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let addr = format!("{}:{}", ip, port);

        // TCP connect with timeout
        let stream = match tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };

        // Implicit TLS (SMTPS) on 465
        if port == 465 {
            let sni = extract_sni_hint(ip, None);
            let tls_stream = upgrade_to_tls(stream, sni).await.ok()?;
            return fingerprint_smtp_tls(ip, port, tls_stream).await;
        }

        // Plain SMTP first (25/587)
        let mut stream = stream;

        // Banner
        let banner = read_chunk(&mut stream).await?;
        let fields = SmtpBannerParser::parse(&banner);
        let mut evidence = format_evidence("smtp", fields);


        // EHLO (plain)
        stream.write_all(b"EHLO example.com\r\n").await.ok()?;
        let ehlo_plain = read_multiline(&mut stream).await.unwrap_or_default();
        push_line(&mut evidence, "EHLO (plain)", ehlo_plain.trim());

        // STARTTLS negotiation
        if ehlo_plain.contains("STARTTLS") {
            stream.write_all(b"STARTTLS\r\n").await.ok()?;
            let starttls_reply = read_multiline(&mut stream).await.unwrap_or_default();
            push_line(&mut evidence, "STARTTLS reply", starttls_reply.trim());

            if starttls_reply.starts_with("220") {
                let sni = extract_sni_hint(ip, Some(&banner));
            
                if let Ok(tls_stream) = upgrade_to_tls(stream, sni).await {
                    return fingerprint_smtp_tls_with_evidence(ip, port, tls_stream, evidence).await;
                } else {
                     // TLS failed, still return what we have
                     return Some(ServiceFingerprint::from_banner(ip, port, "smtp", evidence));
                }
            }
        }

        Some(ServiceFingerprint::from_banner(ip, port, "smtp", evidence))
    }

    fn ports(&self) -> Vec<u16> { vec![25, 587, 465] }
    fn name(&self) -> &'static str { "smtp" }
}

// Upgrade a TcpStream to TLS via OpenSSL (tokio-openssl requires Pin and async connect)
async fn upgrade_to_tls(stream: TcpStream, sni: String) -> Result<SslStream<TcpStream>, ()> {
    let connector = SslConnector::builder(SslMethod::tls()).map_err(|_| ())?.build();
    let ssl = connector.configure().map_err(|_| ())?
        .into_ssl(&sni).map_err(|_| ())?;

    // Own the TLS stream
    let mut tls = SslStream::new(ssl, stream).map_err(|_| ())?;

    // Pin a separate reference for connect(); do not shadow the owned variable
    let mut pinned = std::pin::Pin::new(&mut tls);
    pinned.as_mut().connect().await.map_err(|_| ())?;

    // Return the owned stream
    Ok(tls)
}




// After TLS upgrade, collect banner (if any) and EHLO (TLS)
async fn fingerprint_smtp_tls(ip: &str, port: u16, mut tls_stream: SslStream<TcpStream>) -> Option<ServiceFingerprint> {
    let mut evidence = String::new();

    if let Some(tls_banner) = read_chunk_tls(&mut tls_stream).await {
        push_line(&mut evidence, "Banner (TLS)", tls_banner.trim());
    }

    tls_stream.write_all(b"EHLO example.com\r\n").await.ok()?;
    let ehlo_tls = read_multiline_tls(&mut tls_stream).await.unwrap_or_default();
    push_line(&mut evidence, "EHLO (TLS)", ehlo_tls.trim());

    Some(ServiceFingerprint::from_banner(ip, port, "smtp", evidence))
}

async fn fingerprint_smtp_tls_with_evidence(
    ip: &str,
    port: u16,
    mut tls_stream: SslStream<TcpStream>,
    mut evidence: String,
) -> Option<ServiceFingerprint> {
    if let Some(tls_banner) = read_chunk_tls(&mut tls_stream).await {
        push_line(&mut evidence, "Banner (TLS)", tls_banner.trim());
    }

    // Re‑EHLO after STARTTLS
    tls_stream.write_all(b"EHLO example.com\r\n").await.ok()?;
    let ehlo_tls = read_multiline_tls(&mut tls_stream).await.unwrap_or_default();
    push_line(&mut evidence, "EHLO (TLS)", ehlo_tls.trim());

    Some(ServiceFingerprint::from_banner(ip, port, "smtp", evidence))
}


// Simple chunk readers
async fn read_chunk(stream: &mut TcpStream) -> Option<String> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await.ok()?;
    if n == 0 { return None; }
    Some(String::from_utf8_lossy(&buf[..n]).to_string())
}

async fn read_chunk_tls(stream: &mut SslStream<TcpStream>) -> Option<String> {
    let mut buf = [0u8; 4096];
    // Use a small timeout to avoid indefinite hang if server doesn’t send a TLS banner
    let n = match tokio::time::timeout(Duration::from_millis(200), stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
                        _ => return None,
        };

    if n == 0 { return None; }
    Some(String::from_utf8_lossy(&buf[..n]).to_string())
}

// Multiline readers (no closures; direct loops with timeouts)
async fn read_multiline(stream: &mut TcpStream) -> Option<String> {
    let mut out = String::new();
    let mut buf = [0u8; 4096];

    let n = stream.read(&mut buf).await.ok()?;
    if n == 0 { return None; }
    out.push_str(&String::from_utf8_lossy(&buf[..n]));

    loop {
        let last = out.lines().last().unwrap_or("");
        if is_final_reply(last) || !is_multiline_reply(last) {
            break;
        }
        let more = tokio::time::timeout(Duration::from_millis(200), stream.read(&mut buf)).await.ok();
        match more {
            Some(Ok(m)) if m > 0 => out.push_str(&String::from_utf8_lossy(&buf[..m])),
            _ => break,
        }
    }
    Some(out)
}

async fn read_multiline_tls(stream: &mut SslStream<TcpStream>) -> Option<String> {
    let mut out = String::new();
    let mut buf = [0u8; 4096];

    let n = stream.read(&mut buf).await.ok()?;
    if n == 0 { return None; }
    out.push_str(&String::from_utf8_lossy(&buf[..n]));

    loop {
        let last = out.lines().last().unwrap_or("");
        if is_final_reply(last) || !is_multiline_reply(last) {
            break;
        }
        let more = tokio::time::timeout(Duration::from_millis(200), stream.read(&mut buf)).await.ok();
        match more {
            Some(Ok(m)) if m > 0 => out.push_str(&String::from_utf8_lossy(&buf[..m])),
            _ => break,
        }
    }
    Some(out)
}

// Helpers
fn is_multiline_reply(line: &str) -> bool {
    // "250-PIPELINING"
    line.len() >= 4 && line.get(3..4) == Some("-")
}

fn is_final_reply(line: &str) -> bool {
    // "250 PIPELINING"
    line.len() >= 4 && line.get(3..4) == Some(" ")
}

fn extract_sni_hint(ip: &str, banner_opt: Option<&str>) -> String {
    if let Some(banner) = banner_opt {
        let mut parts = banner.split_whitespace();
        if parts.next() == Some("220") {
            if let Some(host) = parts.next() {
                if host.contains('.') {
                    return host.to_string();
                }
            }
        }
    }
    // Fallback to a harmless placeholder if IP
    if ip.parse::<std::net::IpAddr>().is_ok() {
        "example.com".to_string()
    } else {
        ip.to_string()
    }
}

fn push_line(out: &mut String, label: &str, value: &str) {
    if !out.is_empty() { out.push('\n'); }
    out.push_str(label);
    out.push_str(": ");
    out.push_str    (value);
}