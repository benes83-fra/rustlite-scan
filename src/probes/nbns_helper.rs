use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

/// Result entry for a single NetBIOS name record returned by NBSTAT
#[derive(Debug)]
pub struct NbnsNameEntry {
    pub name: String,  // trimmed NetBIOS name
    pub name_type: u8, // name type byte
    pub flags: u16,    // name flags (2 bytes)
}

/// NBNS query result: list of name entries and optional unit id (MAC)
#[derive(Debug)]
pub struct NbnsResult {
    pub names: Vec<NbnsNameEntry>,
    pub unit_id: Option<[u8; 6]>,
}

/// Encode the NetBIOS wildcard name "*" into the RFC1002 "first label" format.
/// Returns the encoded label bytes (length + 32 encoded chars + 0x00 terminator).
fn encode_nbns_wildcard_label() -> Vec<u8> {
    // NetBIOS name is 16 bytes; wildcard is "*" followed by 15 spaces
    let mut name16 = [b' '; 16];
    name16[0] = b'*';
    // Each byte is encoded as two ASCII chars: high nibble + 'A', low nibble + 'A'
    let mut encoded = Vec::with_capacity(1 + 32 + 1);
    encoded.push(32u8); // length of the encoded label (32)
    for &b in &name16 {
        let hi = ((b >> 4) & 0x0F) + b'A';
        let lo = (b & 0x0F) + b'A';
        encoded.push(hi);
        encoded.push(lo);
    }
    encoded.push(0u8); // terminator
    encoded
}

/// Send NBSTAT query to ip:137 and parse response. timeout_ms is per-operation timeout.
/// Returns Ok(NbnsResult) on success (names may be empty if no useful data), Err on socket/timeout errors.
pub async fn nbns_query(
    ip: &str,
    timeout_ms: u64,
) -> Result<NbnsResult, Box<dyn std::error::Error + Send + Sync>> {
    // Bind ephemeral UDP socket on all interfaces
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let addr: std::net::SocketAddr = format!("{}:137", ip).parse()?;

    eprintln!("NBNS: nbns_query start for {}", addr);

    // Build NBNS header + question
    // Header: Transaction ID (2), Flags (2), QDCOUNT (2), ANCOUNT (2), NSCOUNT (2), ARCOUNT (2)

    let txid: u16 = {
        let mut rng = StdRng::from_entropy();
        rng.gen()
    };
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&txid.to_be_bytes()); // Transaction ID
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Flags = 0 (standard query)
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    // Question: encoded wildcard name + QTYPE + QCLASS
    let label = encode_nbns_wildcard_label();
    pkt.extend_from_slice(&label);
    pkt.extend_from_slice(&0x0021u16.to_be_bytes()); // QTYPE = NBSTAT (0x0021)
    pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // QCLASS = IN (0x0001)
    fn hex_dump(b: &[u8]) -> String {
        b.iter()
            .map(|x| format!("{:02x}", x))
            .collect::<Vec<_>>()
            .join("")
    }
    eprintln!("NBNS: outgoing pkt hex: {}", hex_dump(&pkt));
    let mut pkt2: Vec<u8> = vec![
        0x31, 0x38, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x00, 0x00, 0x21, 0x00, 0x01,
    ];

    pkt2[0..2].copy_from_slice(&txid.to_be_bytes());
    eprintln!("{:?}", pkt);
    eprintln!("{:?}", pkt2);
    // Send packet
    let to = Duration::from_millis(timeout_ms * 10);

    let sent = timeout(to, sock.send_to(&pkt, &addr)).await??;
    eprintln!(
        "NBNS: sent {} bytes to {}.. as {}",
        sent,
        addr,
        hex_dump(&pkt)
    );

    // Receive response
    let mut buf = vec![0u8; 1500];

    eprintln!("Receiving buffer to {:?}", sock);

    let recv_res = tokio::time::timeout(to, sock.recv_from(&mut buf)).await;

    let (n, _peer) = match recv_res {
        Ok(Ok((n, peer))) => {
            eprintln!("NBNS: got {} bytes from {}", n, peer);
            (n, peer)
        }
        Ok(Err(e)) => {
            eprintln!("NBNS: recv_from error: {}", e);
            return Ok(NbnsResult {
                names: Vec::new(),
                unit_id: None,
            });
        }
        Err(_) => {
            eprintln!("NBNS: recv_from timed out after {} ms", timeout_ms);
            return Ok(NbnsResult {
                names: Vec::new(),
                unit_id: None,
            });
        }
    };

    buf.truncate(n);

    eprintln!("Buf after send is :{:?}", buf);

    // Basic header checks
    if buf.len() < 12 {
        eprintln!("Header is too short {}", buf.len());
        return Ok(NbnsResult {
            names: Vec::new(),
            unit_id: None,
        });
    }
    let resp_txid = u16::from_be_bytes([buf[0], buf[1]]);
    if resp_txid != txid {
        // not our response; ignore
        eprintln!("resp_txid !=txid");
        return Ok(NbnsResult {
            names: Vec::new(),
            unit_id: None,
        });
    }
    let _qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    if ancount == 0 {
        eprintln!("Returing ancount == 0");
        return Ok(NbnsResult {
            names: Vec::new(),
            unit_id: None,
        });
    }

    // Skip question section: start at offset 12
    let mut pos = 12usize;
    // Skip encoded name label(s): read until a 0x00 terminator
    while pos < buf.len() {
        let len = buf[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        // skip len bytes
        pos = pos.saturating_add(len);
    }
    // After terminator, skip QTYPE(2) + QCLASS(2)
    pos = pos.saturating_add(4);
    if pos >= buf.len() {
        return Ok(NbnsResult {
            names: Vec::new(),
            unit_id: None,
        });
    }

    // Now parse answer RRs. We only need the first NBSTAT answer's RDATA.
    // Answers are in DNS-like format: NAME (2 bytes pointer often), TYPE(2), CLASS(2), TTL(4), RDLENGTH(2), RDATA(...)
    let mut names = Vec::new();
    let mut unit_id: Option<[u8; 6]> = None;

    for _ in 0..ancount {
        if pos + 10 > buf.len() {
            break;
        } // need at least NAME(2) TYPE(2) CLASS(2) TTL(4) RDLEN(2)
          // NAME: could be pointer (0xC0 xx) or label; skip appropriately
        if buf[pos] & 0xC0 == 0xC0 {
            // pointer: 2 bytes
            pos += 2;
        } else {
            // label sequence: skip until 0x00
            while pos < buf.len() {
                let l = buf[pos] as usize;
                pos += 1;
                if l == 0 {
                    break;
                }
                pos = pos.saturating_add(l);
            }
        }
        if pos + 8 > buf.len() {
            break;
        }
        let _rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let _rclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        let _ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        pos += 8;
        if pos + 2 > buf.len() {
            break;
        }
        let rdlen = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2;
        if pos + rdlen > buf.len() {
            break;
        }

        // For NBSTAT (TYPE 0x0021), RDATA format:
        // 1 byte: number of names (n)
        // n * 18 bytes: each name entry: 15 bytes name, 1 byte name type, 2 bytes flags
        // followed by unit id (6 bytes)
        if rdlen >= 1 {
            let rdata_start = pos;
            let n_names = buf[rdata_start] as usize;
            let mut p = rdata_start + 1;
            for _ in 0..n_names {
                if p + 18 > pos + rdlen {
                    break;
                }
                // name is 15 bytes (p..p+15), may be padded with spaces
                let raw_name = &buf[p..p + 15];
                // trim trailing spaces and non-printable
                let name = String::from_utf8_lossy(raw_name).trim_end().to_string();
                let name_type = buf[p + 15];
                let flags = u16::from_be_bytes([buf[p + 16], buf[p + 17]]);
                names.push(NbnsNameEntry {
                    name,
                    name_type,
                    flags,
                });
                p += 18;
            }
            // unit id (MAC) is last 6 bytes of RDATA if present and rdlen >= 1 + n*18 + 6
            let expected_unit_offset = rdata_start + 1 + n_names * 18;
            if rdlen >= (1 + n_names * 18 + 6) && expected_unit_offset + 6 <= pos + rdlen {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&buf[expected_unit_offset..expected_unit_offset + 6]);
                unit_id = Some(mac);
            }
        }

        pos += rdlen;
    }
    eprintln!(
        "NBNS: nbns_query done for {} -> names={}, unit_id={:?}",
        ip,
        names.len(),
        unit_id
    );

    Ok(NbnsResult { names, unit_id })
}
