use tokio::time::{timeout, Duration};
use tokio::net::UdpSocket;
use std::collections::HashMap;
use std::net::{SocketAddr, Ipv4Addr};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read};

use crate::probes::{Probe, ProbeContext, helper::{connect_with_timeout, push_line}};
use crate::service::ServiceFingerprint;

pub struct MdnsProbe;

#[async_trait::async_trait]
impl Probe for MdnsProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        // mDNS is multicast-based; we will send a discovery query and listen for responses.
        // We keep evidence and conservative confidence.
        let mut evidence = String::new();
        let mut confidence: u8 = 40;

        // Use a short listen window to avoid long blocking
        let listen_ms = std::cmp::min(timeout_ms, 1500);

        // Build a simple DNS PTR query for _services._dns-sd._udp.local
        let query_name = "_services._dns-sd._udp.local";
        let query = build_mdns_ptr_query(query_name);

        // Bind UDP socket to ephemeral port and join multicast group
        // Use 0.0.0.0:0 so kernel picks an ephemeral port
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => {
                push_line(&mut evidence, "mdns", "bind_error");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "mdns", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        // Set multicast TTL to 1 (local link)
        let _ = socket.set_multicast_ttl_v4(1);

        // Send to mDNS multicast address
        let mdns_addr: SocketAddr = SocketAddr::from(([224, 0, 0, 251], 5353));
        if socket.send_to(&query, mdns_addr).await.is_err() {
            push_line(&mut evidence, "mdns", "send_error");
            let mut fp = ServiceFingerprint::from_banner(ip, port, "mdns", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }

        // Listen for responses for listen_ms milliseconds
        let mut buf = vec![0u8; 1500];
        let mut services: HashMap<String, Vec<String>> = HashMap::new(); // service -> TXT entries
        let mut srvs: HashMap<String, Vec<String>> = HashMap::new(); // service -> SRV targets

        let listen_dur = Duration::from_millis(listen_ms);
        let start = tokio::time::Instant::now();

        loop {
            let remaining = listen_dur.checked_sub(start.elapsed());
            if remaining.is_none() { break; }
            let to = remaining.unwrap();

            match timeout(to, socket.recv_from(&mut buf)).await {
                Ok(Ok((n, _src))) => {
                    if n == 0 { continue; }
                    if let Some(parsed) = parse_mdns_response(&buf[..n]) {
                        // parsed: (ptrs, srvs, txts) where ptrs: Vec<String> service types
                        for svc in parsed.ptrs {
                            services.entry(svc.clone()).or_insert_with(Vec::new);
                        }
                        for (svc, txts) in parsed.txts.into_iter() {
                            let entry = services.entry(svc.clone()).or_insert_with(Vec::new);
                            for t in txts { if !entry.contains(&t) { entry.push(t); } }
                        }
                        for (svc, targets) in parsed.srvs.into_iter() {
                            let entry = srvs.entry(svc.clone()).or_insert_with(Vec::new);
                            for t in targets { if !entry.contains(&t) { entry.push(t); } }
                        }
                    }
                }
                _ => break, // timeout or error -> stop listening
            }
        }

        // Emit evidence
        if !services.is_empty() {
            push_line(&mut evidence, "mdns", "services_found");
            for (svc, txts) in services.iter() {
                push_line(&mut evidence, "mdns_service", svc);
                if let Some(srv_targets) = srvs.get(svc) {
                    for t in srv_targets {
                        push_line(&mut evidence, "mdns_srv", &format!("{} -> {}", svc, t));
                    }
                }
                for t in txts {
                    push_line(&mut evidence, "mdns_txt", &format!("{} -> {}", svc, t));
                }
            }
            confidence = 70;
            let mut fp = ServiceFingerprint::from_banner(ip, port, "mdns", evidence);
            fp.confidence = confidence;
            return Some(fp);
        } else {
            push_line(&mut evidence, "mdns", "no_services");
            let mut fp = ServiceFingerprint::from_banner(ip, port, "mdns", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }
    }

    async fn probe_with_ctx(&self, ip: &str, port: u16, ctx: ProbeContext) -> Option<ServiceFingerprint> {
        self.probe(
            ip,
            port,
            ctx.get("timeout_ms").and_then(|s| s.parse::<u64>().ok()).unwrap_or(1500),
        ).await
    }

    fn ports(&self) -> Vec<u16> { vec![5353] }
    fn name(&self) -> &'static str { "mdns" }
}

// ----------------- helpers -----------------

fn build_mdns_ptr_query(name: &str) -> Vec<u8> {
    // Build a minimal DNS query (no EDNS, no TSIG)
    // ID = 0 (mDNS typically uses 0), flags = 0x0000 (standard query), QDCOUNT=1
    let mut buf = Vec::new();
    WriteBytesExt::write_u16::<BigEndian>(&mut buf, 0).unwrap(); // id
    WriteBytesExt::write_u16::<BigEndian>(&mut buf, 0).unwrap(); // flags
    WriteBytesExt::write_u16::<BigEndian>(&mut buf, 1).unwrap(); // qdcount
    WriteBytesExt::write_u16::<BigEndian>(&mut buf, 0).unwrap(); // ancount
    WriteBytesExt::write_u16::<BigEndian>(&mut buf, 0).unwrap(); // nscount
    WriteBytesExt::write_u16::<BigEndian>(&mut buf, 0).unwrap(); // arcount

    // encode qname
    for label in name.split('.') {
        let l = label.len() as u8;
        buf.push(l);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // end of name

    // QTYPE = PTR (12), QCLASS = IN (1) with QU bit for mDNS? Use IN (1)
    WriteBytesExt::write_u16::<BigEndian>(&mut buf, 12).unwrap();
    WriteBytesExt::write_u16::<BigEndian>(&mut buf, 1).unwrap();

    buf
}

struct ParsedMdns {
    ptrs: Vec<String>,
    srvs: HashMap<String, Vec<String>>,
    txts: HashMap<String, Vec<String>>,
}

fn parse_mdns_response(packet: &[u8]) -> Option<ParsedMdns> {
    // Minimal, defensive DNS parser: header + answers.
    // Handles name decoding with compression pointers.
    let mut cursor = Cursor::new(packet);

    // Header
    let _id = cursor.read_u16::<BigEndian>().ok()?;
    let _flags = cursor.read_u16::<BigEndian>().ok()?;
    let qdcount = cursor.read_u16::<BigEndian>().ok()?;
    let ancount = cursor.read_u16::<BigEndian>().ok()?;
    let _nscount = cursor.read_u16::<BigEndian>().ok()?;
    let _arcount = cursor.read_u16::<BigEndian>().ok()?;

    // Skip questions
    for _ in 0..qdcount {
        let _ = read_name(packet, &mut cursor)?;
        // skip qtype/qclass
        cursor.read_u16::<BigEndian>().ok()?;
        cursor.read_u16::<BigEndian>().ok()?;
    }

    let mut ptrs = Vec::new();
    let mut srvs: HashMap<String, Vec<String>> = HashMap::new();
    let mut txts: HashMap<String, Vec<String>> = HashMap::new();

    for _ in 0..ancount {
        let name = read_name(packet, &mut cursor)?;
        let rtype = cursor.read_u16::<BigEndian>().ok()?;
        let _class = cursor.read_u16::<BigEndian>().ok()?;
        let _ttl = cursor.read_u32::<BigEndian>().ok()?;
        let rdlen = cursor.read_u16::<BigEndian>().ok()? as usize;

        let rdata_start = cursor.position() as usize;
        let rdata_end = rdata_start + rdlen;
        if rdata_end > packet.len() { return None; }

        match rtype {
            12 => { // PTR
                // rdata is a domain name
                let mut r_cursor = Cursor::new(&packet[rdata_start..]);
                // read_name expects full packet and cursor positioned at start offset
                // so we need to create a cursor that references the full packet but with position set
                // Instead, call read_name with the main cursor moved to rdata_start
                cursor.set_position(rdata_start as u64);
                if let Some(target) = read_name(packet, &mut cursor) {
                    // name is the service type, target is instance name
                    if !ptrs.contains(&name) {
                        ptrs.push(name.clone());
                    }
                    // store TXT/SRV under the instance name later; also map service type -> instance
                    // We'll use the instance name as key for TXT/SRV mapping
                    // For now, ensure maps have the instance key
                    srvs.entry(target.clone()).or_insert_with(Vec::new);
                    txts.entry(target.clone()).or_insert_with(Vec::new);
                }
                // ensure cursor at end of rdata
                cursor.set_position(rdata_end as u64);
            }
            33 => { // SRV
                // priority(2) weight(2) port(2) target(name)
                let mut rcur = Cursor::new(&packet[rdata_start..rdata_end]);
                let _priority = rcur.read_u16::<BigEndian>().ok()?;
                let _weight = rcur.read_u16::<BigEndian>().ok()?;
                let port = rcur.read_u16::<BigEndian>().ok()?;
                // target name decoding requires full packet and absolute offset
                // compute absolute offset of target in original packet
                let target_offset = rdata_start + 6;
                let mut main_cursor = Cursor::new(packet);
                main_cursor.set_position(target_offset as u64);
                if let Some(target) = read_name(packet, &mut main_cursor) {
                    // associate SRV target with the owner name (the 'name' variable)
                    let entry = srvs.entry(name.clone()).or_insert_with(Vec::new);
                    entry.push(format!("{}:{}", target, port));
                }
                cursor.set_position(rdata_end as u64);
            }
            16 => { // TXT
                // TXT is a sequence of length-prefixed strings
                let mut off = rdata_start;
                while off < rdata_end {
                    let len = *packet.get(off)? as usize;
                    off += 1;
                    if off + len > rdata_end { break; }
                    let txt = String::from_utf8_lossy(&packet[off..off+len]).to_string();
                    let entry = txts.entry(name.clone()).or_insert_with(Vec::new);
                    if !entry.contains(&txt) { entry.push(txt); }
                    off += len;
                }
                cursor.set_position(rdata_end as u64);
            }
            _ => {
                // skip unknown types
                cursor.set_position(rdata_end as u64);
            }
        }
    }

    Some(ParsedMdns { ptrs, srvs, txts })
}

// Read a DNS name from packet using cursor; supports compression pointers.
// Returns the decoded name as a dot-separated string.
// Read a DNS name from packet using cursor; supports compression pointers.
// Returns the decoded name as a dot-separated string or None on parse error.
fn read_name(packet: &[u8], cursor: &mut Cursor<&[u8]>) -> Option<String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut jump_pos = 0usize;
    let mut seen = 0usize;

    loop {
        // guard against runaway loops
        if seen > packet.len() { return None; }
        let pos = cursor.position() as usize;
        let b = *packet.get(pos)?;
        if b & 0xC0 == 0xC0 {
            // pointer
            let b2 = *packet.get(pos + 1)?;
            let offset = (((b & 0x3F) as usize) << 8) | (b2 as usize);
            if !jumped {
                jump_pos = pos + 2;
            }
            // validate offset
            if offset >= packet.len() { return None; }
            cursor.set_position(offset as u64);
            jumped = true;
            seen += 2;
            continue;
        } else if b == 0 {
            if !jumped {
                cursor.set_position(pos as u64 + 1);
            } else {
                cursor.set_position(jump_pos as u64);
            }
            break;
        } else {
            let len = b as usize;
            let start = pos + 1;
            let end = start + len;
            let slice = packet.get(start..end)?;
            let label = String::from_utf8_lossy(slice).to_string();
            labels.push(label);
            if !jumped {
                cursor.set_position(end as u64);
            } else {
                // when jumped, advance to jump_pos so we don't loop forever
                cursor.set_position(jump_pos as u64);
            }
            seen += len + 1;
        }
    }

    Some(labels.join("."))
}
