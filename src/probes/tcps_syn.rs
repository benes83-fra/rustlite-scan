use async_trait::async_trait;
use crate::probes::{Probe, ProbeContext};
use crate::service::ServiceFingerprint;
use std::net::IpAddr;
use std::os::raw::c_ushort;
use pnet::datalink;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::MutablePacket;
use pnet::packet::Packet;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv4::checksum as ipchecksum;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::tcp::TcpFlags;
use std::convert::TryInto;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
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




    pub fn hex_line (buf : &[u8]) -> String {
        buf.iter().map(|b| format!("{:02x}",b)).collect::<Vec<_>>().join(" ")
    }

    pub fn resolve_mac(interface: &datalink::NetworkInterface, target_ip: Ipv4Addr) -> Option<[u8; 6]> {
        let source_mac = interface.mac?.octets();
        let source_ip = interface.ips.iter().find_map(|ip| {
            if let std::net::IpAddr::V4(v4) = ip.ip() {
                Some(v4)
            } else {
                None
            }
        })?;

        let mut arp_buf = [0u8; 42];
        {
            let mut eth = MutableEthernetPacket::new(&mut arp_buf[..]).unwrap();
            eth.set_destination([0xff; 6].into()); // broadcast
            eth.set_source(source_mac.into());
            eth.set_ethertype(EtherTypes::Arp);

            let mut arp = MutableArpPacket::new(eth.payload_mut()).unwrap();
            arp.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp.set_protocol_type(EtherTypes::Ipv4);
            arp.set_hw_addr_len(6);
            arp.set_proto_addr_len(4);
            arp.set_operation(ArpOperations::Request);
            arp.set_sender_hw_addr(source_mac.into());
            arp.set_sender_proto_addr(source_ip.octets().into());
            arp.set_target_hw_addr([0u8; 6].into());
            arp.set_target_proto_addr(target_ip.octets().into());
        }

        // Send ARP request
    
        let config = datalink::Config::default();
        let channel = datalink::channel(interface, config).ok()?;

        let (mut tx, mut rx) = match channel {
            datalink::Channel::Ethernet(tx, rx) => (tx, rx),
            _ => return None,
        };
        match tx.send_to(&arp_buf, None){
            Some(Ok(())) => {},
            _ => return None,
        };

        // Wait for ARP reply
        let start = std::time::Instant::now();
        while start.elapsed().as_millis() < 500 {
            if let Ok(packet) = rx.next() {
                if let Some(mut eth) = MutableEthernetPacket::new(packet.to_vec().as_mut_slice()) {
                    if eth.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = ArpPacket::new(eth.payload_mut()) {
                            if arp.get_operation() == ArpOperations::Reply &&
                            arp.get_sender_proto_addr() == target_ip {
                                return Some(arp.get_sender_hw_addr().octets());
                            }
                        }
                    }
                }
            }
        }

        None
    }

    use pnet::packet::ipv4::checksum as ipv4_checksum;
    use pnet::packet::tcp::ipv4_checksum as tcp_ipv4_checksum;
    pub fn compute_checksums(syn: &mut [u8], local_ip: Ipv4Addr, target_ip: Ipv4Addr) {
        let ihl = (syn[0] & 0x0f) as usize;
        let ip_header_len = ihl * 4;
        let tcp_offset = ip_header_len;

        {
            let mut ip_pkt = MutableIpv4Packet::new(&mut syn[..ip_header_len]).expect("ip header");
            ip_pkt.set_checksum(0);
            let csum = ipv4_checksum(&ip_pkt.to_immutable());
            ip_pkt.set_checksum(csum);
        }

        {
            let mut tcp_pkt = MutableTcpPacket::new(&mut syn[tcp_offset..]).expect("tcp header");
            tcp_pkt.set_checksum(0);
            let tcp_csum = tcp_ipv4_checksum(&tcp_pkt.to_immutable(), &local_ip, &target_ip);
            tcp_pkt.set_checksum(tcp_csum);
        }
        {
           

            let ip_pkt = Ipv4Packet::new(&syn[..ip_header_len]).unwrap();
            eprintln!("Computed IP checksum: 0x{:04x}", ip_pkt.get_checksum());
            let tcp_pkt = TcpPacket::new(&syn[tcp_offset..]).unwrap();
            eprintln!("Computed TCP checksum: 0x{:04x}", tcp_pkt.get_checksum());
        }
    }




#[cfg(all(feature = "syn_fingerprint"))]
mod win {
    
    use super::tcp_syn_helper::{build_syn_packet, parse_tcp_meta_ipv4};
    use crate::service::ServiceFingerprint;
    use pcap::{Active, Capture, Device};
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
    use tokio::task;
    use std::net::IpAddr;
    use std::os::raw::c_ushort;
    use pnet::datalink;
    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
    use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
    use pnet::packet::MutablePacket;
    use pnet::packet::Packet;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::ipv4::checksum as ipchecksum;
    use pnet::packet::tcp::MutableTcpPacket;
    use pnet::packet::tcp::TcpFlags;
    use std::convert::TryInto;
    use crate::probes::tcps_syn::{hex_line, resolve_mac,compute_checksums};

    
 


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
        let mut device = real_dev;
        let mut cap: Capture<Active> =
            Capture::from_device(device.clone()).ok()?
            .immediate_mode(true)
            .snaplen(5000)
            .open().ok()?;
        cap = cap.setnonblock().ok()?;
        let stats  = cap.stats().unwrap().clone();
    

        let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
        sock.connect(SocketAddrV4::new(ip, port)).ok()?;
        let local_ip = match sock.local_addr().ok()? {
            std::net::SocketAddr::V4(sa) => *sa.ip(),
            _ => return None,
        };
        let src_port: u16 = 40000 + (port % 20000);
        let mut syn = build_syn_packet(local_ip, ip, src_port, port);
        let filter = format!(
            "tcp and src host {} and src port {} and dst host {} and dst port {}",
            ip, port, local_ip, src_port
        );
        cap.filter(&filter, true).ok()?;
        
    // Resolve MAC
        let ihl = (syn[0] & 0x0f) as usize;
        let ip_header_len = ihl * 4;
        let tcp_offset = ip_header_len;
        let ip_src: Ipv4Addr = local_ip;
        let ip_dst: Ipv4Addr = ip;

        compute_checksums(&mut syn, local_ip, ip);

        // Optional debug prints: verify checksums before sending
        
        
        let iface_name = device.name.clone();
        let interfaces = datalink::interfaces();
        let iface = interfaces.into_iter().find(|i| i.name == iface_name)?;
        eprintln! ("pnet interface name:{}",iface.name);
        
        if let Some(mac) = iface.mac{
            eprintln! ("source MAC (iface):{}",mac);
        }else{
            eprintln! ("source MAC  missing on iface!");
        }

        let target_mac = resolve_mac(&iface, ip)?;
        let source_mac = iface.mac?.octets();
        eprintln! ("resolved target MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);
        // Build Ethernet frame
        let mut frame = vec![0u8; 14 + syn.len()];
        {
            let mut eth = MutableEthernetPacket::new(&mut frame[..]).unwrap();
            eth.set_destination(target_mac.into());
            eth.set_source(source_mac.into());
            eth.set_ethertype(EtherTypes::Ipv4);

            eth.payload_mut().copy_from_slice(&syn);
        }
        eprintln!("Build Eithernet frame (len={}): {}", frame.len(), hex_line(&frame));
        // Send full Ethernet frame
        match cap.sendpacket(&frame[..]){
            Ok(()) => eprintln!("cap.sendpacket OK"),
            Err(e) => eprintln!("cap.sendpacket ERROR: {:?}",e),
        }
            let stat2 = cap.stats().unwrap().clone();
        eprintln! ("After sym packet sent {:?}", stat2);
        let start = std::time::Instant::now();
        while start.elapsed().as_millis() < 6000 {
            if let Ok(pkt) = cap.next_packet() {
                eprintln! ("Packet: {:?}",pkt );
                let data = pkt.data;
                
                if data.len() < 14 {
                    continue;
                }
                let ip_slice = &data[14..];


                if let Some(meta) = parse_tcp_meta_ipv4(ip_slice) {
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

#[cfg(all(feature = "syn_fingerprint"))]
use win::tcp_syn_fingerprint;





// Fallback stub 
#[cfg(not(feature = "syn_fingerprint"))] 
pub async fn tcp_syn_fingerprint(_ip: &str, _port: u16) -> Option<ServiceFingerprint> { 
    None 
}

