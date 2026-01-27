    use pnet_packet::ip::IpNextHeaderProtocols;
    use pnet_packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
    use pnet_packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
    use std::net::Ipv4Addr;
    use pnet_packet::Packet;
    


    

    #[derive(Debug)]
    pub struct TcpMeta {
        pub ttl: u8,
        pub window: u32,
        pub mss: Option<u16>,
        pub df: bool,

        pub ts: bool,
        pub ws: Option<u8>,
        pub sackok: bool,
        pub ecn: bool,

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
            tcp.set_data_offset(5);
            tcp.set_flags(TcpFlags::SYN);
            tcp.set_window(64240);
            // checksum left zero; acceptable for our purpose
        }
        buf
    }

 
pub fn parse_tcp_meta_ipv4(ip_slice: &[u8]) -> Option<TcpMeta> {
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::tcp::TcpPacket;

    let ip = Ipv4Packet::new(ip_slice)?;
    if ip.get_version() != 4 {
        return None;
    }

    let ttl = ip.get_ttl();
    let df = ip.get_flags() & 0x2 != 0; // DF bit

    let src_ip = ip.get_source();
    let dst_ip = ip.get_destination();

    let ip_header_len = (ip.get_header_length() * 4) as usize;
    if ip_slice.len() < ip_header_len {
        return None;
    }

    let tcp_slice = &ip_slice[ip_header_len..];
    let tcp = TcpPacket::new(tcp_slice)?;

    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();
    let window = tcp.get_window() as u32;

    // -----------------------------
    // TCP flags → ECN detection
    // -----------------------------
    let flags = tcp.get_flags();
    let ecn = (flags & 0x40 != 0) || (flags & 0x80 != 0); // ECE or CWR

    // -----------------------------
    // Parse TCP options
    // -----------------------------
    let data_offset = tcp.get_data_offset() as usize * 4;
    if data_offset < 20 || data_offset > tcp_slice.len() {
        return None;
    }

    let opts = &tcp_slice[20..data_offset];

    let mut mss = None;
    let mut ws = None;
    let mut sackok = false;
    let mut ts = false;

    let mut i = 0;
    while i < opts.len() {
        let kind = opts[i];

        match kind {
            0 => break, // End of options
            1 => { i += 1; continue; } // NOP

            2 => { // MSS
                if i + 4 <= opts.len() {
                    mss = Some(u16::from_be_bytes([opts[i+2], opts[i+3]]));
                }
                i += 4;
            }

            3 => { // Window Scale
                if i + 3 <= opts.len() {
                    ws = Some(opts[i+2]);
                }
                i += 3;
            }

            4 => { // SACK Permitted
                sackok = true;
                i += 2;
            }

            8 => { // Timestamps
                if i + 10 <= opts.len() {
                    ts = true;
                }
                i += 10;
            }

            _ => {
                // Unknown option → skip length
                if i + 2 <= opts.len() {
                    let len = opts[i+1] as usize;
                    if len < 2 { break; }
                    i += len;
                } else {
                    break;
                }
            }
        }
    }

    Some(TcpMeta {
        ttl,
        window,
        mss,
        df,
        ts,
        ws,
        sackok,
        ecn,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    })
}




