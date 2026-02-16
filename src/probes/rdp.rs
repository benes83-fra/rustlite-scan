use async_trait::async_trait;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::Probe;
use crate::probes::tls::fingerprint_tls;
use crate::{probes::ProbeContext, service::ServiceFingerprint};
use openssl::ssl::{SslConnector, SslMethod};
use tokio_openssl::SslStream;

pub struct RdpProbe;

#[async_trait]
impl Probe for RdpProbe {
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

        let mut stream = match tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return None,
        };

        // Send negotiation request
        let nego_request: [u8; 19] = [
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08,
            0x00, 0x03, 0x00, 0x00, 0x00,
        ];
        stream.write_all(&nego_request).await.ok()?;

        let mut buf = [0u8; 1024];
        let _n = tokio::time::timeout(Duration::from_millis(500), stream.readable())
            .await
            .ok()?;
        let n = stream.try_read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }

        let (proto_str, selected_proto) = decode_rdp_response(&buf[..n]);

        // If TLS selected, upgrade
        if selected_proto == 0x01 || selected_proto == 0x02 {
            if let Ok(tls_stream) = upgrade_to_tls(stream, ip).await {
                // Reuse your TLS fingerprinting helper
                return fingerprint_tls(ip, port, "rdp", proto_str, tls_stream).await;
            }
        }

        // Otherwise just return negotiation evidence
        Some(ServiceFingerprint::from_banner(ip, port, "rdp", proto_str))
    }

    fn ports(&self) -> Vec<u16> {
        vec![3389]
    }
    fn name(&self) -> &'static str {
        "rdp"
    }
}

fn decode_rdp_response(data: &[u8]) -> (String, u32) {
    if data.len() < 15 {
        return (format!("RDP_raw: {:02x?}", data), 0);
    }
    let proto = u32::from_be_bytes([data[11], data[12], data[13], data[14]]);
    let proto_str = match proto {
        0x00 => "RDP (Standard)",
        0x01 => "SSL (TLS)",
        0x02 => "CredSSP (NLA)",
        _ => "Unknown",
    };
    (
        format!(
            "RDP_negotiation: type={:#04x}, flags={:#04x}, selectedProtocol={:#x} ({})",
            data[7], data[8], proto, proto_str
        ),
        proto,
    )
}

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
