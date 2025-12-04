use async_trait::async_trait;
use tokio::net::UdpSocket;
use std::net::SocketAddr;
use std::time::Duration;
use crate::service::ServiceFingerprint;
use super::Probe;

pub struct DnsProbe;

#[async_trait]
impl Probe for DnsProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let addr: SocketAddr = format!("{}:{}", ip, port).parse().ok()?;
        let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
        socket.connect(addr).await.ok()?;

        // Build a simple DNS query for version.bind in CHAOS class
        let query = build_version_bind_query();
        socket.send(&query).await.ok()?;

        let mut buf = [0u8; 512];
        let n =match  tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            socket.recv(&mut buf)
        ).await {
            Ok(Ok(n)) => n,
                    _ => return None, // timeout or recv error
        };

        let evidence = parse_dns_response(&buf[..n]);
        Some(ServiceFingerprint::from_banner(ip, port, "dns", evidence))
    }

    fn ports(&self) -> Vec<u16> { vec![53] }
    fn name(&self) -> &'static str { "dns" }
}

// Helper: build a DNS query packet for version.bind
fn build_version_bind_query() -> Vec<u8> {
    // Transaction ID
    let mut packet = vec![0x12, 0x34];
    // Flags: standard query
    packet.extend_from_slice(&[0x01, 0x00]);
    // QDCOUNT = 1
    packet.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT, NSCOUNT, ARCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // QNAME: "version.bind"
    for label in ["version", "bind"] {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // end of QNAME

    // QTYPE = TXT (16)
    packet.extend_from_slice(&[0x00, 0x10]);
    // QCLASS = CHAOS (3)
    packet.extend_from_slice(&[0x00, 0x03]);

    packet
}

// Helper: parse response minimally
fn parse_dns_response(resp: &[u8]) -> String {
    if resp.len() < 12 {
        return "invalid dns response".to_string();
    }
    let rcode = resp[3] & 0x0F;
    format!("DNS response code {}", rcode)
}


