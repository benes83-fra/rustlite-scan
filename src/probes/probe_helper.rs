use tokio::net::TcpStream;
use tokio::io::{ AsyncWriteExt};
use std::time::Duration;
use openssl::ssl::{SslConnector, SslMethod};
use tokio_openssl::SslStream;

use crate::probes::tls::fingerprint_tls;

/// Send request, read response, optionally upgrade to TLS, return evidence
pub async fn probe_exchange_tls(
    ip: &str,
    port: u16,
    timeout_ms: u64,
    request: &[u8],
    protocol: &str,
    decode_fn: fn(&[u8]) -> String,
    try_tls: bool,
) -> Option<String> {
    let addr = format!("{}:{}", ip, port);

    let mut stream = match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(&addr),
    ).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    // Send request
    if stream.write_all(request).await.is_err() {
        return None;
    }

    // Read response
    let mut buf = [0u8; 2048];
    let n = match tokio::time::timeout(Duration::from_millis(1000), stream.readable()).await {
        Ok(_) => stream.try_read(&mut buf).unwrap_or(0),
        Err(_) => 0,
    };
    if n == 0 {
        return Some(format!("{}_no_response", protocol));
    }

    let mut evidence = decode_fn(&buf[..n]);

    // If TLS requested, upgrade
    if try_tls {
        if let Ok(tls_stream) = upgrade_to_tls(stream, ip).await {
            if let Some(fp) = fingerprint_tls(ip, port, protocol, evidence.clone(), tls_stream).await {
                if let Some(ev) = fp.evidence {
                    evidence.push_str(&ev);
                }
            }
        }
    }

    Some(evidence)
}

async fn upgrade_to_tls(stream: TcpStream, sni: &str) -> Result<SslStream<TcpStream>, ()> {
    let connector = SslConnector::builder(SslMethod::tls()).map_err(|_| ())?.build();
    let ssl = connector.configure().map_err(|_| ())?.into_ssl(sni).map_err(|_| ())?;
    let mut tls = SslStream::new(ssl, stream).map_err(|_| ())?;
    let mut pinned = std::pin::Pin::new(&mut tls);
    pinned.as_mut().connect().await.map_err(|_| ())?;
    Ok(tls)
}
