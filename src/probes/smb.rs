use tokio::net::TcpStream;
use tokio::time::{timeout, Duration, sleep};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use crate::service::ServiceFingerprint;
use super::Probe;
use crate::probes::helper::push_line;

/// Minimal SMB probe: negotiate and extract lightweight evidence.
/// - Connects to TCP/445
/// - Sends a conservative SMB1 Negotiate request (dialect "NT LM 0.12")
/// - Detects SMB1 vs SMB2/3 by response signature
/// - Extracts ASCII evidence strings and any SMB2 GUID-like bytes
pub struct SmbProbe;

const DEBUG: bool = true;
const CONNECT_TIMEOUT_MS: u64 = 1500;
const IO_TIMEOUT_MS: u64 = 1500;

impl SmbProbe {
    /// Build a conservative SMB1 Negotiate Protocol Request that asks for "NT LM 0.12".
    /// This function builds the same wire bytes used by many lightweight scanners.
    fn build_smb1_negotiate() -> Vec<u8> {
        // Dialect string "NT LM 0.12" encoded as: 0x02 <len> <ascii bytes> 0x00
        // We'll construct a minimal SMB1 Negotiate request:
        // NetBIOS session header (4 bytes) + SMB header + WordCount/ByteCount + dialects
        // This is intentionally minimal and conservative.
        let dialect = b"\x02NT LM 0.12\x00";

        // SMB header (32 bytes total after NetBIOS header)
        // Protocol: 0xFF 'S' 'M' 'B'
        // Command: 0x72 (Negotiate)
        // Rest: mostly zeros for a minimal request
        let mut smb_header = vec![
            0xFF, b'S', b'M', b'B', // protocol
            0x72, // command: Negotiate
            0x00, 0x00, 0x00, 0x00, // status
            0x18, // flags (example)
            0x01, 0x28, // flags2 (example: support unicode etc) - conservative
            0x00, 0x00, // PIDHigh
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Security features (8)
            0x00, 0x00, // Reserved
            0x00, 0x00, // TID
            0x2F, 0x4B, // PIDLow (random-ish)
            0x00, 0x00, // UID
            0x00, 0x00, // MID
        ];

        // WordCount = 0x00 (no parameters)
        let word_count = vec![0x00u8];

        // ByteCount = length of dialects
        let byte_count = (dialect.len() as u16).to_be_bytes().to_vec();

        // Assemble payload (SMB header + WordCount + ByteCount + dialects)
        let mut payload = Vec::new();
        payload.extend_from_slice(&smb_header);
        payload.extend_from_slice(&word_count);
        payload.extend_from_slice(&byte_count);
        payload.extend_from_slice(dialect);

        // NetBIOS session service header: 4 bytes, first is 0x00, next 3 bytes are length
        let len = payload.len();
        let mut netbios = vec![0x00u8];
        netbios.extend_from_slice(&((len as u32).to_be_bytes()[1..])); // 3 bytes length

        let mut pkt = Vec::new();
        pkt.extend_from_slice(&netbios);
        pkt.extend_from_slice(&payload);
        pkt
    }

    /// Send bytes over TCP and wait for a response (with retries). Returns received bytes or None.
    async fn send_and_recv_tcp(addr: &str, req: &[u8], timeout_ms: u64, attempts: usize) -> Option<Vec<u8>> {
        // Resolve and connect with timeout
        let mut rng = StdRng::from_entropy();
        for attempt in 1..=attempts {
            if DEBUG { eprintln!("SMB: attempt {} connect -> {}", attempt, addr); }
            match timeout(Duration::from_millis(CONNECT_TIMEOUT_MS), TcpStream::connect(addr)).await {
                Ok(Ok(mut stream)) => {
                    if DEBUG { eprintln!("SMB: connected, sending {} bytes", req.len()); }
                    if let Err(e) = stream.try_write(req) {
                        eprintln!("SMB: write error: {}", e);
                        return None;
                    }
                    // wait for response
                    let mut buf = vec![0u8; 8192];
                    match timeout(Duration::from_millis(timeout_ms.max(IO_TIMEOUT_MS)), stream.readable()).await {
                        Ok(Ok(())) => {
                            // try to read
                            match stream.try_read(&mut buf) {
                                Ok(n) if n > 0 => {
                                    buf.truncate(n);
                                    if DEBUG { eprintln!("SMB: recv {} bytes preview={:02x?}", n, &buf[..std::cmp::min(128, buf.len())]); }
                                    return Some(buf);
                                }
                                Ok(_) => {
                                    if DEBUG { eprintln!("SMB: read returned 0 bytes"); }
                                }
                                Err(e) => {
                                    eprintln!("SMB: read error: {}", e);
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            eprintln!("SMB: readable wait error: {}", e);
                        }
                        Err(_) => {
                            if DEBUG { eprintln!("SMB: recv timeout on attempt {}", attempt); }
                        }
                    }
                }
                Ok(Err(e)) => {
                    eprintln!("SMB: connect error: {}", e);
                }
                Err(_) => {
                    if DEBUG { eprintln!("SMB: connect timed out on attempt {}", attempt); }
                }
            }

            // jittered backoff
            if attempt < attempts {
                let backoff = 100 + (rng.gen_range(0..150));
                sleep(Duration::from_millis(backoff)).await;
            }
        }
        None
    }

    /// Heuristic parser: detect SMB1 vs SMB2/3 and extract ASCII evidence strings.
    /// - SMB1 signature: 0xFF 'S' 'M' 'B' after NetBIOS header (offset 4)
    /// - SMB2 signature: 0xFE 'S' 'M' 'B' after NetBIOS header (offset 4)
    /// - Extract ASCII substrings (Windows, Samba, etc.) and any 16-byte GUID-like sequences for SMB2.
    fn parse_smb_response(resp: &[u8]) -> (Option<&'static str>, Vec<(String, String)>) {
        let mut evidence = Vec::new();
        // Ensure we have at least 8 bytes to inspect NetBIOS + signature
        if resp.len() >= 8 {
            // If NetBIOS header present (first byte 0x00), signature starts at offset 4
            let sig_off = if resp[0] == 0x00 { 4usize } else { 0usize };
            if resp.len() > sig_off + 3 {
                let sig = &resp[sig_off .. sig_off + 4];
                if sig == [0xFF, b'S', b'M', b'B'] {
                    // SMB1
                    // Try to find ASCII strings in the payload (NativeOS, NativeLanMan)
                    let ascii = SmbProbe::extract_ascii_strings(resp);
                    for s in ascii {
                        evidence.push(("SMB1_ascii".to_string(), s));
                    }
                    return (Some("SMB1"), evidence);
                } else if sig == [0xFE, b'S', b'M', b'B'] {
                    // SMB2/3
                    // Try to find a 16-byte Server GUID in the response (common in SMB2 NEGOTIATE)
                    if resp.len() >= sig_off + 64 {
                        // heuristic: server GUID often appears in negotiate response near offset ~40..56
                        let guid_slice = &resp[sig_off + 40 .. std::cmp::min(resp.len(), sig_off + 56)];
                        if guid_slice.len() >= 16 {
                            // format as hex
                            let guid_hex = guid_slice[..16].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
                            evidence.push(("SMB2_server_guid".to_string(), guid_hex));
                        }
                    }
                    // extract ASCII strings too
                    let ascii = SmbProbe::extract_ascii_strings(resp);
                    for s in ascii {
                        evidence.push(("SMB2_ascii".to_string(), s));
                    }
                    return (Some("SMB2/3"), evidence);
                } else {
                    // Unknown signature: still try to extract ASCII
                    let ascii = SmbProbe::extract_ascii_strings(resp);
                    for s in ascii {
                        evidence.push(("SMB_unknown_ascii".to_string(), s));
                    }
                    return (None, evidence);
                }
            }
        }

        // fallback: extract ASCII strings if any
        let ascii = SmbProbe::extract_ascii_strings(resp);
        for s in ascii {
            evidence.push(("SMB_raw_ascii".to_string(), s));
        }
        (None, evidence)
    }

    /// Extract printable ASCII substrings of length >= 4 from the buffer (heuristic).
    fn extract_ascii_strings(buf: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = Vec::new();
        for &b in buf {
            if b.is_ascii_graphic() || b == b' ' {
                cur.push(b);
            } else {
                if cur.len() >= 4 {
                    if let Ok(s) = String::from_utf8(cur.clone()) {
                        // filter trivial tokens
                        let s_trim = s.trim().to_string();
                        if !s_trim.is_empty() {
                            out.push(s_trim);
                        }
                    }
                }
                cur.clear();
            }
        }
        if cur.len() >= 4 {
            if let Ok(s) = String::from_utf8(cur.clone()) {
                let s_trim = s.trim().to_string();
                if !s_trim.is_empty() {
                    out.push(s_trim);
                }
            }
        }
        out
    }
    /// Build a minimal SMB2 NEGOTIATE request (NetBIOS header + SMB2 header + dialects).
    /// This is conservative: asks for dialect 0x0202 (SMB 2.0.2) and 0x0300 (SMB 3.0).
    fn build_smb2_negotiate() -> Vec<u8> {
        // NetBIOS session header (4 bytes): 0x00 + 3-byte length
        // We'll construct SMB2 NEGOTIATE payload then prefix with NetBIOS header.
        // SMB2 header is 64 bytes; we fill required fields conservatively.
        let mut payload = Vec::new();

        // SMB2 header (64 bytes)
        // Protocol: 0xFE 'S' 'M' 'B'
        payload.extend_from_slice(&[0xFE, b'S', b'M', b'B']);
        // StructureSize (2 bytes) = 64 (0x0040)
        payload.extend_from_slice(&0x0040u16.to_le_bytes());
        // CreditCharge (2), ChannelSequence (2), Reserved (4)
        payload.extend_from_slice(&[0u8; 8]);
        // Command: 0x0000 (NEGOTIATE)
        payload.extend_from_slice(&0x0000u16.to_le_bytes());
        // CreditsRequested (2), Flags (4), NextCommand (4)
        payload.extend_from_slice(&[0u8; 10]);
        // MessageId (8)
        payload.extend_from_slice(&[0u8; 8]);
        // Reserved2 (4), TreeId (4), SessionId (8)
        payload.extend_from_slice(&[0u8; 16]);
        // Signature (16)
        payload.extend_from_slice(&[0u8; 16]);

        // SMB2 NEGOTIATE request body (variable)
        // StructureSize (2) = 36 (0x0024)
        payload.extend_from_slice(&0x0024u16.to_le_bytes());
        // DialectCount (2) -> we will include two dialects
        payload.extend_from_slice(&0x0002u16.to_le_bytes());
        // SecurityMode (2) - 0
        payload.extend_from_slice(&0x0000u16.to_le_bytes());
        // Reserved (2)
        payload.extend_from_slice(&[0u8; 2]);
        // Capabilities (4) - 0
        payload.extend_from_slice(&0u32.to_le_bytes());
        // ClientGuid (16) - random
        let mut rng = StdRng::from_entropy();
        let mut guid = [0u8; 16];
        for b in guid.iter_mut() { *b = rng.gen(); }
        payload.extend_from_slice(&guid);
        // NegotiateContextOffset (4) and NegotiateContextCount (2) and Reserved (2)
        // For simplicity we won't use contexts; set offsets to 0
        payload.extend_from_slice(&[0u8; 8]);

        // Dialects (each 2 bytes, little-endian)
        // 0x0202 = SMB 2.0.2, 0x0300 = SMB 3.0.0
        payload.extend_from_slice(&0x0202u16.to_le_bytes());
        payload.extend_from_slice(&0x0300u16.to_le_bytes());

        // Now prefix with NetBIOS header
        let len = payload.len();
        let mut netbios = vec![0x00u8];
        netbios.extend_from_slice(&((len as u32).to_be_bytes()[1..])); // 3 bytes length

        let mut pkt = Vec::new();
        pkt.extend_from_slice(&netbios);
        pkt.extend_from_slice(&payload);
        pkt
    }

    /// Parse an SMB2 NEGOTIATE response (heuristic).
    /// Returns (dialect_hex, server_guid_hex, ascii_strings)
    /// Improved SMB2 negotiate response parser (robust, heuristic).
    /// Returns (dialect_hex_opt, server_guid_hex_opt, ascii_strings).
    /// Map common SMB2 dialect hex values to friendly names.
    pub fn smb2_dialect_name(dialect_hex: &str) -> Option<&'static str> {
        println! ("Dialect_Hex :{:?}",dialect_hex);
        match dialect_hex {
            "0x0202" => Some("SMB 2.0.2"),
            "0x0210" => Some("SMB 2.1"),
            "0x0300" => Some("SMB 3.0"),
            "0x0302" => Some("SMB 3.0.2"),
            "0x0311" => Some("SMB 3.1.1"),
            _ => None,
        }
    }

    /// Spec-aware SMB2 NEGOTIATE parser.
    /// Returns (dialect_hex_opt, dialect_name_opt, server_guid_opt, capabilities_vec, ascii_strings)
    fn parse_smb2_negotiate_spec(resp: &[u8]) -> (Option<String>, Option<String>, Option<String>, Vec<String>, Vec<String>) {
        // 1) find SMB2 signature (0xFE 'S' 'M' 'B')
        let payload_len = if resp.len() >= 4 {
            ((resp[1] as usize) << 16) | ((resp[2] as usize) << 8) | (resp[3] as usize)
        } else {
            0usize
        };
        let total_len = resp.len();
        if DEBUG { eprintln!("SMB: total recv bytes = {}, netbios payload_len = {}", total_len, payload_len); }
        let sig_pos = resp.windows(4).position(|w| w == [0xFE, b'S', b'M', b'B']);
        if sig_pos.is_none() {
            eprintln!("SMB: no SMB2 signature found");
            // no SMB2 signature: fallback to ascii extraction
            let ascii = SmbProbe::extract_ascii_strings(resp);
            return (None, None, None, Vec::new(), ascii);
        }
        let sig_off = sig_pos.unwrap();
        let body_off = sig_off + 4 + 64;
        let mut dialect_hex: Option<String> = None;
        let available_body = if payload_len > 64 { payload_len - 64 } else { 0 };
        if DEBUG { eprintln!("SMB: body_off = {}, available_body = {}", body_off, available_body); }
        if available_body >= 6 && total_len >=body_off + 6{
            let dialect_le = u16::from_le_bytes([resp[body_off + 4], resp[body_off + 5]]);
            if let dialect_hex1 = format!("0x{:04x}", dialect_le){
                eprintln!("SMB: precise dialect read = {}", dialect_hex1);
            }
        }else {
        // 2) dialect detection: scan for known dialect u16 values (little-endian) in the response
            let known_dialects: [u16;5] = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311];
            
            let payload_start = 4usize;
            let payload_end = std::cmp::min(total_len, 4 + payload_len);
            if DEBUG { eprintln!("SMB: constrained scan payload window {}..{}", payload_start, payload_end); }
            
            for i in (sig_off + 4)..resp.len().saturating_sub(1) {
                let v = u16::from_le_bytes([resp[i], resp[i+1]]);
                
                if known_dialects.contains(&v) {
                    dialect_hex = Some(format!("0x{:04x}", v));
                    break;
                }
            }
            if let Some(ref dh) = dialect_hex {
                eprintln!("SMB: dialect found by constrained scan = {}", dh);
                // record dh...
            } else {
                eprintln!("SMB: dialect not found (payload too short for precise parse)");
                // record unknown dialect
            }
        }
        // 3) server GUID extraction: scan for a 16-byte window that is not all zeros/FF and has some entropy
        let mut server_guid: Option<String> = None;
        for i in sig_off..resp.len().saturating_sub(15) {
            let window = &resp[i..i+16];
            let all_zero = window.iter().all(|&b| b == 0);
            let all_ff = window.iter().all(|&b| b == 0xFF);
            if all_zero || all_ff { continue; }
            // require at least 4 nontrivial bytes to avoid false positives
            let nontrivial = window.iter().filter(|&&b| b != 0 && b != 0xFF).count();
            if nontrivial >= 4 {
                let hex = window.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
                server_guid = Some(hex);
                break;
            }
        }

        // 4) capabilities detection: scan for any 4-byte little-endian value and test known capability bits
        // Known SMB2 global capability bits (common values)
        let capability_map: &[(u32, &str)] = &[
            (0x00000001, "DFS"),                 // SMB2_GLOBAL_CAP_DFS
            (0x00000002, "LEASING"),             // SMB2_GLOBAL_CAP_LEASING
            (0x00000004, "LARGE_MTU"),           // SMB2_GLOBAL_CAP_LARGE_MTU
            (0x00000008, "MULTI_CHANNEL"),       // SMB2_GLOBAL_CAP_MULTI_CHANNEL
            (0x00000010, "PERSISTENT_HANDLES"),  // SMB2_GLOBAL_CAP_PERSISTENT_HANDLES
            (0x00000020, "DIRECTORY_LEASING"),   // SMB2_GLOBAL_CAP_DIRECTORY_LEASING
            (0x00000040, "ENCRYPTION"),          // SMB2_GLOBAL_CAP_ENCRYPTION (common flag)
        ];
        let mut capabilities_found: Vec<String> = Vec::new();
        // scan windows of 4 bytes and test bits
        for i in sig_off..resp.len().saturating_sub(3) {
            let v = u32::from_le_bytes([resp[i], resp[i+1], resp[i+2], resp[i+3]]);
            if v == 0 { continue; }
            for &(mask, name) in capability_map {
                if (v & mask) != 0 {
                    if !capabilities_found.iter().any(|s| s == name) {
                        capabilities_found.push(name.to_string());
                    }
                }
            }
            if !capabilities_found.is_empty() {
                break; // stop after first plausible capability word found
            }
        }

        // 5) ASCII substrings for additional evidence
        let ascii = SmbProbe::extract_ascii_strings(resp);
        println!("About to check for dialectname...Hey at {:?}", dialect_hex);
        // 6) friendly dialect name lookup
        let dialect_name = dialect_hex.as_ref().and_then(|h| Self::smb2_dialect_name(h).map(|s| s.to_string()));

        (dialect_hex, dialect_name, server_guid, capabilities_found, ascii)
    }

    

}

#[async_trait::async_trait]
impl Probe for SmbProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let addr = format!("{}:{}", ip, port);

        // Build SMB1 negotiate request (kept conservative)
        let req = SmbProbe::build_smb1_negotiate();

        if DEBUG { eprintln!("SMB: sending negotiate ({} bytes) to {}", req.len(), addr); }

        // Try sending and receiving
        let resp = SmbProbe::send_and_recv_tcp(&addr, &req, timeout_ms, 2).await;

        let mut evidence = String::new();

        let resp = match resp {
            Some(r) => r,
            None => {
                // no response: record that we attempted and move on
                // If SMB1 attempt produced no useful response or connection was closed, try SMB2 negotiate
                        if DEBUG { eprintln!("SMB: trying SMB2 negotiate fallback"); }
                        let req2 = SmbProbe::build_smb2_negotiate();
                        if DEBUG { eprintln!("SMB: sending SMB2 negotiate ({} bytes) to {}", req2.len(), addr); }
                        if let Some(resp2) = SmbProbe::send_and_recv_tcp(&addr, &req2, timeout_ms, 2).await {
                            // parse SMB2 response
                            let (dialect_hex, dialect_name, server_guid, capabilities, ascii) = SmbProbe::parse_smb2_negotiate_spec(&resp2);

                            if let Some(dh) = dialect_hex { push_line(&mut evidence, "SMB2_dialect", &dh); }
                            if let Some(dn) = dialect_name { push_line(&mut evidence, "SMB2_dialect_name", &dn); }
                            if let Some(g) = server_guid { push_line(&mut evidence, "SMB2_server_guid", &g); }
                            if !capabilities.is_empty() {
                                push_line(&mut evidence, "SMB2_capabilities", &capabilities.join(", "));
                            }
                            for s in ascii {
                                push_line(&mut evidence, "SMB2_ascii", &s);
                            }

                            return Some(ServiceFingerprint::from_banner(ip, port, "smb", evidence));
                        } else {
                            // still no response from SMB2 either
                            push_line(&mut evidence, "SMB_probe", "no_response");
                            return Some(ServiceFingerprint::from_banner(ip, port, "smb", evidence));
}

            }
        };

        // Parse response heuristically
        let (version_opt, items) = SmbProbe::parse_smb_response(&resp);

        if let Some(v) = version_opt {
            push_line(&mut evidence, "SMB_version_detected", v);
        } else {
            push_line(&mut evidence, "SMB_version_detected", "unknown");
        }

        for (k, v) in items {
            push_line(&mut evidence, &k, &v);
        }

        // If we found nothing useful, include a short raw preview for debugging
        if evidence.is_empty() {
            push_line(&mut evidence, "SMB_raw", &format!("{:02x?}", &resp[..std::cmp::min(128, resp.len())]));
        }

        Some(ServiceFingerprint::from_banner(ip, port, "smb", evidence))
    }

    fn ports(&self) -> Vec<u16> { vec![445] }
    fn name(&self) -> &'static str { "smb" }
}
