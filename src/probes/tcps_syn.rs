use async_trait::async_trait;
use crate::probes::{Probe, ProbeContext};
use crate::service::ServiceFingerprint;
use crate::probes::tcp_syn_helper;
pub struct TcpSynProbe;

#[async_trait]
impl Probe for TcpSynProbe {
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
        tcp_syn_fingerprint(ip, port).await
    }

    fn ports(&self) -> Vec<u16> {
        vec![] // run on any open TCP port
    }

    fn name(&self) -> &'static str {
        "tcp_syn"
    }
}




// ---------- Windows/Npcap implementation ----------

#[cfg(all(feature = "syn_fingerprint", target_os = "windows"))]
mod win {
    
    use super::tcp_syn_helper::{build_syn_packet, parse_tcp_meta_ipv4};
    use crate::service::ServiceFingerprint;
    use pcap::{Active, Capture, Device};
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
    use tokio::task;
     use std::net::IpAddr;
    use std::os::raw::c_ushort;
   

 


    pub async fn tcp_syn_fingerprint(ip: &str, port: u16) -> Option<ServiceFingerprint> {
        let ip = ip.parse::<Ipv4Addr>().ok()?;
        task::spawn_blocking(move || tcp_syn_fingerprint_blocking(ip, port))
            .await
            .ok()
            .flatten()
    }

    fn tcp_syn_fingerprint_blocking(ip: Ipv4Addr, port: u16) -> Option<ServiceFingerprint> {
        // pick first device for now; can be refined later
        let dev = Device::lookup().ok()??;

        

       let local_ip = {
            let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
            sock.connect(SocketAddrV4::new(ip, port)).ok()?;
            match sock.local_addr().ok()? {
                std::net::SocketAddr::V4(sa) => *sa.ip(),
                _ => return None,
            }
        };

        let real_dev = Device::list().ok()?
            .into_iter()
            .find(|d| {
                d.addresses.iter().any(|a| {
                    match a.addr {
                        IpAddr::V4(ipv4) => ipv4 == local_ip,
                        _ => false,
                    }
                })
            })
            .expect("No Npcap device matches the local routing IP");




        
        let mut cap: Capture<Active> = Capture::from_device(real_dev).ok()?.immediate_mode(true).open().ok()?;
        cap =cap.setnonblock().ok()?;
        let stats  = cap.stats().unwrap().clone();
        eprintln!("Captures stats {:?}",stats);
        // derive our local IPv4 address via a UDP "connect" trick
        let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
        sock.connect(SocketAddrV4::new(ip, port)).ok()?;
        let local_ip = match sock.local_addr().ok()? {
            std::net::SocketAddr::V4(sa) => *sa.ip(),
            _ => return None,
        };

        let src_port: u16 = 40000 + (port % 20000);
        let syn = build_syn_packet(local_ip, ip, src_port, port);

        // BPF filter: only TCP from target IP/port to our IP/src_port
        let filter = format!(
            "tcp and src host {} and src port {} and dst host {} and dst port {}",
            ip, port, local_ip, src_port
        );
        cap.filter(&filter, true).ok()?;

        cap.sendpacket(syn).ok()?;

        let start = std::time::Instant::now();
        while start.elapsed().as_millis() < 1500 {
            if let Ok(pkt) = cap.next_packet() {
                 eprintln! ("Packet: {:?}", pkt);
                if let Some(meta) = parse_tcp_meta_ipv4(pkt.data) {
                    
                    // sanity check: match our 4‑tuple
                    if meta.src_ip != ip
                        || meta.dst_ip != local_ip
                        || meta.src_port != port
                        || meta.dst_port != src_port
                    {
                        continue;
                    }
                    eprintln! ("Meta : {:?}", meta);
                    let mut ev = String::new();
                    ev.push_str(&format!("tcp_syn_ttl: {}\n", meta.ttl));
                    ev.push_str(&format!("tcp_syn_window: {}\n", meta.window));
                    if let Some(mss) = meta.mss {
                        ev.push_str(&format!("tcp_syn_mss: {}\n", mss));
                    }
                    ev.push_str(&format!("tcp_syn_df: {}\n", meta.df));

                    let mut fp = ServiceFingerprint::from_banner(
                        &ip.to_string(),
                        port,
                        "tcp_syn",
                        ev,
                    );
                    fp.confidence = 40; // tune later in OS inference
                    return Some(fp);
                }
            }
        }
        None
    }
}

#[cfg(all(feature = "syn_fingerprint", target_os = "windows"))]
use win::tcp_syn_fingerprint;



// ---------- Unix/libpcap implementation ----------

// ---------- Unix/libpcap implementation ----------

#[cfg(all(
    feature = "syn_fingerprint",
    any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )
))]
mod unix {
    use super::tcp_syn_helper::{build_syn_packet, parse_tcp_meta_ipv4};
    use crate::service::ServiceFingerprint;
    use pcap::{Active, Capture, Device};
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
    use tokio::task;

    pub async fn tcp_syn_fingerprint(ip: &str, port: u16) -> Option<ServiceFingerprint> {
        let ip = ip.parse::<Ipv4Addr>().ok()?;
        task::spawn_blocking(move || tcp_syn_fingerprint_blocking(ip, port))
            .await
            .ok()
            .flatten()
    }

    fn tcp_syn_fingerprint_blocking(ip: Ipv4Addr, port: u16) -> Option<ServiceFingerprint> {
        let _dev = Device::lookup().ok()??;

        let local_ip = {
            let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
            sock.connect(SocketAddrV4::new(ip, port)).ok()?;
            match sock.local_addr().ok()? {
                std::net::SocketAddr::V4(sa) => *sa.ip(),
                _ => return None,
            }
        };

        let real_dev = Device::list().ok()?
            .into_iter()
            .find(|d| {
                d.addresses.iter().any(|a| {
                    match a.addr {
                        IpAddr::V4(ipv4) => ipv4 == local_ip,
                        _ => false,
                    }
                })
            })
            .unwrap_or_else(|| {
                // Fallback: just use lookup() if matching by IP fails
                Device::lookup().ok().flatten().expect("No pcap device available")
            });

        let mut cap: Capture<Active> =
            Capture::from_device(real_dev).ok()?.immediate_mode(true).open().ok()?;
        cap = cap.setnonblock().ok()?;

        let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
        sock.connect(SocketAddrV4::new(ip, port)).ok()?;
        let local_ip = match sock.local_addr().ok()? {
            std::net::SocketAddr::V4(sa) => *sa.ip(),
            _ => return None,
        };

        let src_port: u16 = 40000 + (port % 20000);
        let syn = build_syn_packet(local_ip, ip, src_port, port);

        let filter = format!(
            "tcp and src host {} and src port {} and dst host {} and dst port {}",
            ip, port, local_ip, src_port
        );
        cap.filter(&filter, true).ok()?;
        cap.sendpacket(syn).ok()?;

        let start = std::time::Instant::now();
        while start.elapsed().as_millis() < 1500 {
            if let Ok(pkt) = cap.next_packet() {
                if let Some(meta) = parse_tcp_meta_ipv4(pkt.data) {
                    if meta.src_ip != ip
                        || meta.dst_ip != local_ip
                        || meta.src_port != port
                        || meta.dst_port != src_port
                    {
                        continue;
                    }

                    let mut ev = String::new();
                    ev.push_str(&format!("tcp_syn_ttl: {}\n", meta.ttl));
                    ev.push_str(&format!("tcp_syn_window: {}\n", meta.window));
                    if let Some(mss) = meta.mss {
                        ev.push_str(&format!("tcp_syn_mss: {}\n", mss));
                    }
                    ev.push_str(&format!("tcp_syn_df: {}\n", meta.df));

                    let mut fp = ServiceFingerprint::from_banner(
                        &ip.to_string(),
                        port,
                        "tcp_syn",
                        ev,
                    );
                    fp.confidence = 40;
                    return Some(fp);
                }
            }
        }
        None
    }
}

// ---------- selection ----------

#[cfg(all(feature = "syn_fingerprint", target_os = "windows"))]
use win::tcp_syn_fingerprint;

#[cfg(all(
    feature = "syn_fingerprint",
    any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )
))]
use unix::tcp_syn_fingerprint;

#[cfg(any(not(feature = "syn_fingerprint"), not(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))))]
pub async fn tcp_syn_fingerprint(_ip: &str, _port: u16) -> Option<ServiceFingerprint> {
    None
}
