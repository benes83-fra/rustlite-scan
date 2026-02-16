// src/probes/tcp_rst.rs

use crate::probes::{Probe, ProbeContext};
use crate::service::ServiceFingerprint;
use async_trait::async_trait;

#[cfg(feature = "syn_fingerprint")]
mod rstcap {
    use super::*;
    use pcap::{Active, Capture, Device};
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, TcpStream};
    use std::time::{Duration, Instant};
    use tokio::task;

    pub async fn tcp_rst_fingerprint(ip: &str, port: u16) -> Option<ServiceFingerprint> {
        let ip = ip.parse::<Ipv4Addr>().ok()?;
        task::spawn_blocking(move || tcp_rst_fingerprint_blocking(ip, port))
            .await
            .ok()
            .flatten()
    }

    fn tcp_rst_fingerprint_blocking(ip: Ipv4Addr, port: u16) -> Option<ServiceFingerprint> {
        // -----------------------------
        // 1. Find pcap device for local IP
        // -----------------------------
        let local_ip = {
            let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
            sock.connect(SocketAddrV4::new(ip, port)).ok()?;
            match sock.local_addr().ok()? {
                std::net::SocketAddr::V4(sa) => *sa.ip(),
                _ => return None,
            }
        };

        let dev = Device::list()
            .ok()?
            .into_iter()
            .find(|d| {
                d.addresses.iter().any(|a| match a.addr {
                    IpAddr::V4(v4) => v4 == local_ip,
                    _ => false,
                })
            })
            .unwrap_or_else(|| {
                Device::lookup()
                    .ok()
                    .flatten()
                    .expect("No pcap device available")
            });

        let mut cap: Capture<Active> = Capture::from_device(dev.clone())
            .ok()?
            .immediate_mode(true)
            .snaplen(5000)
            .open()
            .ok()?;
        cap = cap.setnonblock().ok()?;

        // -----------------------------
        // 2. Filter for RST packets from target
        // -----------------------------
        let filter = format!("tcp and src host {} and tcp[tcpflags] & tcp-rst != 0", ip);
        cap.filter(&filter, true).ok()?;

        // -----------------------------
        // 3. Trigger a SYN using kernel TCP
        // -----------------------------
        let start = Instant::now();
        let _ = TcpStream::connect_timeout(
            &std::net::SocketAddr::V4(SocketAddrV4::new(ip, port)),
            Duration::from_millis(500),
        );

        // -----------------------------
        // 4. Wait for RST packet
        // -----------------------------
        while start.elapsed().as_millis() < 6000 {
            if let Ok(pkt) = cap.next_packet() {
                let data = pkt.data;
                if data.len() < 34 {
                    continue;
                }

                // Ethernet(14) + IPv4 header
                let ip_slice = &data[14..];
                if ip_slice.len() < 20 {
                    continue;
                }

                let ttl = ip_slice[8];
                let df = (u16::from_be_bytes([ip_slice[6], ip_slice[7]]) & 0x4000) != 0;

                let ihl = (ip_slice[0] & 0x0f) as usize * 4;
                if ip_slice.len() < ihl + 14 {
                    continue;
                }

                let tcp = &ip_slice[ihl..];
                if tcp.len() < 14 {
                    continue;
                }

                let window = u16::from_be_bytes([tcp[14], tcp[15]]) as u32;

                let rst_time = start.elapsed().as_micros();

                // -----------------------------
                // 5. Build evidence
                // -----------------------------
                let mut ev = String::new();
                ev.push_str(&format!("tcp_rst_ttl: {}\n", ttl));
                ev.push_str(&format!("tcp_rst_window: {}\n", window));
                ev.push_str(&format!("tcp_rst_df: {}\n", df));
                ev.push_str(&format!("tcp_rst_time: {}\n", rst_time));

                let mut fp = ServiceFingerprint::from_banner(&ip.to_string(), port, "tcp_rst", ev);
                fp.confidence = 40;
                return Some(fp);
            }
        }

        None
    }
}

#[cfg(not(feature = "syn_fingerprint"))]
mod rstcap {
    use super::*;
    pub async fn tcp_rst_fingerprint(_ip: &str, _port: u16) -> Option<ServiceFingerprint> {
        None
    }
}

pub struct TcpRstProbe;

#[async_trait]
impl Probe for TcpRstProbe {
    async fn probe_with_ctx(
        &self,
        ip: &str,
        port: u16,
        ctx: ProbeContext,
    ) -> Option<ServiceFingerprint> {
        let timeout_ms = ctx
            .get("timeout_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(500);
        self.probe(ip, port, timeout_ms).await
    }

    async fn probe(&self, ip: &str, port: u16, _timeout_ms: u64) -> Option<ServiceFingerprint> {
        rstcap::tcp_rst_fingerprint(ip, port).await
    }

    fn ports(&self) -> Vec<u16> {
        vec![] // run on any TCP port
    }

    fn name(&self) -> &'static str {
        "tcp_rst"
    }
}
