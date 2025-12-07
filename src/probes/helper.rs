use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;
use openssl::ssl::{SslConnector, SslMethod};
use tokio_openssl::SslStream;

use crate::probes::tls::fingerprint_tls;

/// Send request, read response, optionally upgrade to TLS, return evidence.
/// Kept signature compatible with your LdapProbe usage.
pub async fn _probe_exchange_tls(
    ip: &str,
    port: u16,
    timeout_ms: u64,
    request: &[u8],
    protocol: &str,
    decode_fn: fn(&[u8]) -> String,
    try_tls: bool,
) -> Option<String> {
    let addr = format!("{}:{}", ip, port);

    // Connect with timeout
    let mut stream = match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(&addr),
    ).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    // Write request with a short timeout
    if tokio::time::timeout(Duration::from_millis(500), stream.write_all(request)).await.is_err() {
        return None;
    }

    // Read response using a blocking read wrapped in a timeout (more reliable than readable()+try_read)
    let mut buf = vec![0u8; 4096];
    let n = match tokio::time::timeout(Duration::from_millis(1000), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        // No response within timeout — return a marker but keep behavior consistent
        _ => return Some(format!("{}_no_response", protocol)),
    };
    buf.truncate(n);

    // Decode evidence using provided decoder
    let mut evidence = decode_fn(&buf);

    // If TLS requested, only attempt upgrade when the raw response contains the ExtendedResponse tag (0x78)
    if try_tls {
        if buf.iter().any(|&b| b == 0x78) {
            // Use ip as SNI fallback (you can change to a hostname hint if available)
            let sni = ip;
            match upgrade_to_tls(stream, sni).await {
                Ok(tls_stream) => {
                    // fingerprint_tls should return Option-like structure with .evidence
                    if let Some(fp) = fingerprint_tls(ip, port, protocol, evidence.clone(), tls_stream).await {
                        if let Some(ev) = fp.evidence {
                            if !evidence.is_empty() { evidence.push('\n'); }
                            evidence.push_str(&ev);
                        }
                    }
                }
                Err(_) => {
                    // TLS upgrade failed — return the evidence we already have
                }
            }
        } else {
            // Server did not return ExtendedResponse; do not attempt TLS upgrade
        }
    }

    Some(evidence)
}

pub async fn upgrade_to_tls(stream: TcpStream, sni: &str) -> Result<SslStream<TcpStream>, ()> {
    let connector = SslConnector::builder(SslMethod::tls()).map_err(|_| ())?.build();
    let ssl = connector.configure().map_err(|_| ())?.into_ssl(sni).map_err(|_| ())?;
    let mut tls = SslStream::new(ssl, stream).map_err(|_| ())?;
    let mut pinned = std::pin::Pin::new(&mut tls);
    pinned.as_mut().connect().await.map_err(|_| ())?;
    Ok(tls)
}

pub async fn connect_with_timeout(ip: &str, port: u16, timeout_ms: u64) -> Option<TcpStream> {
    let addr = format!("{}:{}", ip, port);
    match tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => Some(stream),
        _ => None,
    }
}

pub fn push_line(out: &mut String, label: &str, value: &str) {
    if !out.is_empty() { out.push('\n'); }
    out.push_str(label);
    out.push_str(": ");
    out.push_str(value);
}
/// Write request to stream and read a single response with timeouts.
/// Returns `Some(Vec<u8>)` when a non-empty response was read, otherwise `None`.
pub async fn send_and_read(stream: &mut TcpStream, request: &[u8], write_timeout_ms: u64, read_timeout_ms: u64) -> Option<Vec<u8>> {
    if tokio::time::timeout(Duration::from_millis(write_timeout_ms), stream.write_all(request)).await.is_err() {
        return None;
    }
    let mut buf = vec![0u8; 8192];
    match tokio::time::timeout(Duration::from_millis(read_timeout_ms), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            buf.truncate(n);
            Some(buf)
        }
        _ => None,
    }
}

/// Map LDAP result codes to readable text.
pub fn ldap_result_text(code: u8) -> &'static str {
    match code {
        0 => "success",
        1 => "operationsError",
        2 => "protocolError",
        3 => "timeLimitExceeded",
        4 => "sizeLimitExceeded",
        7 => "authMethodNotSupported",
        8 => "strongAuthRequired",
        9 => "referralV2",
        10 => "referral",
        16 => "noSuchAttribute",
        32 => "noSuchObject",
        49 => "invalidCredentials",
        50 => "insufficientAccessRights",
        53 => "unwillingToPerform",
        68 => "entryAlreadyExists",
        80 => "other",
        _ => "unknown",
    }
}