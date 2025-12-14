use async_trait::async_trait;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_openssl::SslStream;
use openssl::ssl::{SslConnector, SslMethod};

use crate::probes::ProbeContext;
use crate::service::ServiceFingerprint;
use super::Probe;

pub struct HttpsProbe;

#[async_trait]
impl Probe for HttpsProbe {
    async fn probe_with_ctx (&self, ip : &str , port :u16, ctx :ProbeContext) -> Option <ServiceFingerprint>{
        
        let timeout_ms = ctx.get("timeout_ms").and_then(|s| s.parse::<u64>().ok()).unwrap_or(2000);
        self.probe(ip, port, timeout_ms).await
    }
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let addr = format!("{}:{}", ip, port);
        let connect_deadline = Duration::from_millis(timeout_ms);

        let tcp = match timeout(connect_deadline, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };

        let mut evidence = String::new();

        // Build connector
        let builder = SslConnector::builder(SslMethod::tls()).ok()?;
        // used for debugging in conjunction with  https_probe.rs builder.set_ca_file("tests/ca.crt").unwrap(); // For test purposes, trust our self-signed cert
        let connector = builder.build();
        let mut ssl = connector.configure().ok()?.into_ssl(ip).ok()?;

        ssl.set_verify(openssl::ssl::SslVerifyMode::NONE);

        // Create SslStream and handshake
        let ssl_stream = SslStream::new(ssl, tcp).ok()?;
        let mut pinned = Box::pin(ssl_stream);
        if let Err(e) = pinned.as_mut().connect().await {
            eprintln!("TLS handshake failed: {}", e);
            return None;
        }

        // Extract cert info
        if let Some(cert) = pinned.ssl().peer_certificate() {
            if let Some(entry) = cert.subject_name().entries_by_nid(openssl::nid::Nid::COMMONNAME).next() {
                if let Ok(data) = entry.data().as_utf8() {
                    push_line(&mut evidence, "TLS_subject_cn", &data.to_string());
                }
            }
            if let Some(san_stack) = cert.subject_alt_names() {
                let mut s = String::new();
                for gen in san_stack.iter() {
                    if let Some(dns) = gen.dnsname() {
                        if !s.is_empty() { s.push_str(", "); }
                        s.push_str(dns);
                    }
                }
                if !s.is_empty() { push_line(&mut evidence, "TLS_SANs", &s); }
            }
            push_line(&mut evidence, "TLS_not_before", &cert.not_before().to_string());
            push_line(&mut evidence, "TLS_not_after", &cert.not_after().to_string());
        }

        // Cipher/TLS version/ALPN
        if let Some(cipher) = pinned.ssl().current_cipher() {
            push_line(&mut evidence, "TLS_cipher", cipher.name());
        }
        push_line(&mut evidence, "TLS_version", pinned.ssl().version_str());
        if let Some(alpn) = pinned.ssl().selected_alpn_protocol() {
            let _alpn_str = String::from_utf8_lossy(&alpn);
            push_line(&mut evidence, "TLS_alpn", &String::from_utf8_lossy(&alpn));
        }

        // Recover owned SslStream
        let ssl_stream_owned: SslStream<TcpStream> = *Pin::into_inner(pinned);
        let mut reader = BufReader::new(ssl_stream_owned);

        // Send HTTP GET
        let req = format!("GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: rustlite-scan\r\n\r\n", ip);
        reader.get_mut().write_all(req.as_bytes()).await.ok()?;

        // Read status line
        if let Some(status) = read_line_timeout(&mut reader, Duration::from_secs(2)).await {
            push_line(&mut evidence, "Banner", status.trim());
        }

        // Read headers until blank line
        let mut headers = String::new();
        loop {
            if let Some(h) = read_line_timeout(&mut reader, Duration::from_millis(500)).await {
                if h.trim().is_empty() { break; }
                headers.push_str(&h);
            } else { break; }
        }
        for line in headers.lines() {
            if line.to_lowercase().starts_with("server:") {
                push_line(&mut evidence, "HTTP_Server", line.trim());
            }
        }

        if evidence.is_empty() { None }
        else { Some(ServiceFingerprint::from_banner(ip, port, "https", evidence)) }
    }

    fn ports(&self) -> Vec<u16> { vec![443] }
    fn name(&self) -> &'static str { "https" }
}

// Generic helper
async fn read_line_timeout<R: AsyncBufRead + Unpin>(reader: &mut R, dur: Duration) -> Option<String> {
    let mut line = String::new();
    match timeout(dur, reader.read_line(&mut line)).await {
        Ok(Ok(0)) => None,
        Ok(Ok(_)) => Some(line),
        _ => None,
    }
}

fn push_line(out: &mut String, label: &str, value: &str) {
    if !out.is_empty() { out.push('\n'); }
    out.push_str(label);
    out.push_str(": ");
    out.push_str(value);
}
