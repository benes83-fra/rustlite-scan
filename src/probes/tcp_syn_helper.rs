    use pnet_packet::ip::IpNextHeaderProtocols;
    use pnet_packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
    use pnet_packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
    use pnet_packet::Packet;
    use std::net::Ipv4Addr;

    #[derive(Debug)]
    pub struct TcpMeta {
        pub ttl: u8,
        pub window: u16,
        pub mss: Option<u16>,
        pub df: bool,
        pub src_ip: Ipv4Addr,
        pub dst_ip: Ipv4Addr,
        pub src_port: u16,
        pub dst_port: u16,
    }

    pub fn build_syn_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 40]; // 20 IP + 20 TCP
        {
            let (ip_buf, tcp_buf) = buf.split_at_mut(20);
            let mut ip = MutableIpv4Packet::new(ip_buf).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(40);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip.set_source(src_ip);
            ip.set_destination(dst_ip);
            // checksum left zero; most stacks accept it

            let mut tcp = MutableTcpPacket::new(tcp_buf).unwrap();
            tcp.set_source(src_port);
            tcp.set_destination(dst_port);
            tcp.set_flags(TcpFlags::SYN);
            tcp.set_window(64240);
            // checksum left zero; acceptable for our purpose
        }
        buf
    }

   pub fn parse_tcp_meta_ipv4(packet: &[u8]) -> Option<TcpMeta> {
    let ip = Ipv4Packet::new(packet)?;
    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }

    let ttl = ip.get_ttl();
    let flags = ip.get_flags();
    let df = (flags & 0x2) != 0;

    let src_ip = ip.get_source();
    let dst_ip = ip.get_destination();

    let tcp = TcpPacket::new(ip.payload())?;
    let window = tcp.get_window();
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();

    // -----------------------------
    // MSS parsing from TCP options
    // -----------------------------
    let mut mss: Option<u16> = None;

    let data_offset = tcp.get_data_offset() as usize * 4;
    if data_offset > 20 {
        let opts = &ip.payload()[20..data_offset];

        let mut i = 0;
        while i < opts.len() {
            let kind = opts[i];

            match kind {
                0 => break, // End of options list
                1 => i += 1, // NOP
                2 => {
                    // MSS option
                    if i + 3 < opts.len() {
                        let mss_val = u16::from_be_bytes([opts[i + 2], opts[i + 3]]);
                        mss = Some(mss_val);
                    }
                    break;
                }
                _ => {
                    // Skip unknown option
                    if i + 1 < opts.len() {
                        let len = opts[i + 1] as usize;
                        if len < 2 {
                            break;
                        }
                        i += len;
                    } else {
                        break;
                    }
                }
            }
        }
    }

    Some(TcpMeta {
        ttl,
        window,
        mss,
        df,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    })
}
