use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration, sleep};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use crate::service::ServiceFingerprint;
use super::Probe;
use crate::probes::helper::push_line; // reuse your existing push_line helper

/// SNMP probe that requests sysDescr.0 and sysObjectID.0 via SNMPv2c community "public"
pub struct SnmpProbe;

impl SnmpProbe {
    fn encode_len(len: usize) -> Vec<u8> {
        if len < 128 {
            vec![len as u8]
        } else if len < 256 {
            vec![0x81, len as u8]
        } else {
            panic!("length too large");
        }
    }
    /// Build an SNMPv2c GetBulk request (PDU tag 0xA5).
    /// non_repeaters: usually 0 for walking; max_repetitions: how many GetNext results to request.
    fn build_snmp_getbulk(community: &str, request_id: i32, non_repeaters: i32, max_repetitions: i32) -> Vec<u8> {
        // reuse the same OIDs as before (start points)
        let oid_sysdescr: &[u8] = &[0x2B, 6, 1, 2, 1, 1, 1, 0];
        let oid_sysobject: &[u8] = &[0x2B, 6, 1, 2, 1, 1, 2, 0];

        fn encode_oid_tlv(oid_body: &[u8], encode_len: &dyn Fn(usize) -> Vec<u8>) -> Vec<u8> {
            let mut v = vec![0x06];
            v.extend_from_slice(&encode_len(oid_body.len()));
            v.extend_from_slice(oid_body);
            v
        }

        // varbinds (same pattern: OID + NULL)
        let mut vb1 = Vec::new();
        vb1.extend_from_slice(&encode_oid_tlv(oid_sysdescr, &Self::encode_len));
        vb1.extend_from_slice(&[0x05, 0x00]);

        let mut vb2 = Vec::new();
        vb2.extend_from_slice(&encode_oid_tlv(oid_sysobject, &Self::encode_len));
        vb2.extend_from_slice(&[0x05, 0x00]);

        let mut varbinds = Vec::new();
        for vb in &[vb1, vb2] {
            let mut seq = vec![0x30];
            seq.extend_from_slice(&Self::encode_len(vb.len()));
            seq.extend_from_slice(vb);
            varbinds.extend_from_slice(&seq);
        }
        let mut vbl = vec![0x30];
        vbl.extend_from_slice(&Self::encode_len(varbinds.len()));
        vbl.extend_from_slice(&varbinds);

        // PDU body: request-id, non-repeaters, max-repetitions, varbindlist
        let mut pdu_body = Vec::new();

        // request-id INTEGER
        pdu_body.push(0x02);
        let req_bytes = request_id.to_be_bytes();
        let req_trim = req_bytes.iter().skip_while(|b| **b == 0).cloned().collect::<Vec<u8>>();
        let req_enc = if req_trim.is_empty() { vec![0u8] } else { req_trim };
        pdu_body.extend_from_slice(&Self::encode_len(req_enc.len()));
        pdu_body.extend_from_slice(&req_enc);

        // non-repeaters INTEGER
        pdu_body.push(0x02);
        let nr_bytes = non_repeaters.to_be_bytes();
        let nr_trim = nr_bytes.iter().skip_while(|b| **b == 0).cloned().collect::<Vec<u8>>();
        let nr_enc = if nr_trim.is_empty() { vec![0u8] } else { nr_trim };
        pdu_body.extend_from_slice(&Self::encode_len(nr_enc.len()));
        pdu_body.extend_from_slice(&nr_enc);

        // max-repetitions INTEGER
        pdu_body.push(0x02);
        let mr_bytes = max_repetitions.to_be_bytes();
        let mr_trim = mr_bytes.iter().skip_while(|b| **b == 0).cloned().collect::<Vec<u8>>();
        let mr_enc = if mr_trim.is_empty() { vec![0u8] } else { mr_trim };
        pdu_body.extend_from_slice(&Self::encode_len(mr_enc.len()));
        pdu_body.extend_from_slice(&mr_enc);

        // varbindlist
        pdu_body.extend_from_slice(&vbl);

        // PDU tag for GetBulk is 0xA5
        let mut pdu = vec![0xA5];
        pdu.extend_from_slice(&Self::encode_len(pdu_body.len()));
        pdu.extend_from_slice(&pdu_body);

        // SNMP message wrapper
        let mut msg_body = Vec::new();
        msg_body.extend_from_slice(&[0x02, 0x01, 0x01]); // version = 1 (v2c)
        let comm_bytes = community.as_bytes();
        msg_body.push(0x04);
        msg_body.extend_from_slice(&Self::encode_len(comm_bytes.len()));
        msg_body.extend_from_slice(comm_bytes);
        msg_body.extend_from_slice(&pdu);

        let mut msg = vec![0x30];
        msg.extend_from_slice(&Self::encode_len(msg_body.len()));
        msg.extend_from_slice(&msg_body);

        msg
    }




    /// Build an SNMPv2c GetNextRequest containing the same two varbind OIDs.
    /// PDU tag for GetNext is 0xA1.
    fn build_snmp_getnext(community: &str, request_id: i32) -> Vec<u8> {
        // reuse the same OIDs as in build_snmp_get_sysdescr
        let oid_sysdescr: &[u8] = &[0x2B, 6, 1, 2, 1, 1, 1, 0];
        let oid_sysobject: &[u8] = &[0x2B, 6, 1, 2, 1, 1, 2, 0];

        // helper to encode an OID TLV
        fn encode_oid_tlv(oid_body: &[u8], encode_len: &dyn Fn(usize) -> Vec<u8>) -> Vec<u8> {
            let mut v = vec![0x06];
            v.extend_from_slice(&encode_len(oid_body.len()));
            v.extend_from_slice(oid_body);
            v
        }

        // varbind for sysDescr: OID + NULL
        let mut vb1 = Vec::new();
        vb1.extend_from_slice(&encode_oid_tlv(oid_sysdescr, &Self::encode_len));
        vb1.extend_from_slice(&[0x05, 0x00]); // NULL

        // varbind for sysObjectID: OID + NULL
        let mut vb2 = Vec::new();
        vb2.extend_from_slice(&encode_oid_tlv(oid_sysobject, &Self::encode_len));
        vb2.extend_from_slice(&[0x05, 0x00]); // NULL

        // wrap each varbind in SEQUENCE and then the VarBindList as SEQUENCE of both
        let mut varbinds = Vec::new();
        for vb in &[vb1, vb2] {
            let mut seq = vec![0x30];
            seq.extend_from_slice(&Self::encode_len(vb.len()));
            seq.extend_from_slice(vb);
            varbinds.extend_from_slice(&seq);
        }
        let mut vbl = vec![0x30];
        vbl.extend_from_slice(&Self::encode_len(varbinds.len()));
        vbl.extend_from_slice(&varbinds);

        // PDU: GetNextRequest (0xA1) with request-id, error-status, error-index, varbindlist
        let mut pdu_body = Vec::new();
        // request-id INTEGER
        pdu_body.push(0x02);
        let req_bytes = request_id.to_be_bytes();
        let req_trim = req_bytes.iter().skip_while(|b| **b == 0).cloned().collect::<Vec<u8>>();
        let req_enc = if req_trim.is_empty() { vec![0u8] } else { req_trim };
        pdu_body.extend_from_slice(&Self::encode_len(req_enc.len()));
        pdu_body.extend_from_slice(&req_enc);

        // error-status = 0, error-index = 0
        pdu_body.extend_from_slice(&[0x02, 0x01, 0x00]);
        pdu_body.extend_from_slice(&[0x02, 0x01, 0x00]);

        // varbindlist
        pdu_body.extend_from_slice(&vbl);

        let mut pdu = vec![0xA1];
        pdu.extend_from_slice(&Self::encode_len(pdu_body.len()));
        pdu.extend_from_slice(&pdu_body);

        // SNMP message: SEQUENCE { version INTEGER(1), community OCTET STRING, pdu }
        let mut msg_body = Vec::new();
        msg_body.extend_from_slice(&[0x02, 0x01, 0x01]); // version = 1 (v2c)
        let comm_bytes = community.as_bytes();
        msg_body.push(0x04);
        msg_body.extend_from_slice(&Self::encode_len(comm_bytes.len()));
        msg_body.extend_from_slice(comm_bytes);
        msg_body.extend_from_slice(&pdu);

        let mut msg = vec![0x30];
        msg.extend_from_slice(&Self::encode_len(msg_body.len()));
        msg.extend_from_slice(&msg_body);

        msg
    }




    
    /// Build an SNMPv2c GetRequest containing two varbinds:
    ///  - sysDescr.0  OID 1.3.6.1.2.1.1.1.0
    ///  - sysObjectID.0 OID 1.3.6.1.2.1.1.2.0
    fn build_snmp_get_sysdescr(community: &str, request_id: i32) -> Vec<u8> {
        // OID bytes
        let oid_sysdescr: &[u8] = &[0x2B, 6, 1, 2, 1, 1, 1, 0];
        let oid_sysobject: &[u8] = &[0x2B, 6, 1, 2, 1, 1, 2, 0];

        // helper to encode an OID TLV
        fn encode_oid_tlv(oid_body: &[u8], encode_len: &dyn Fn(usize) -> Vec<u8>) -> Vec<u8> {
            let mut v = vec![0x06];
            v.extend_from_slice(&encode_len(oid_body.len()));
            v.extend_from_slice(oid_body);
            v
        }

        // varbind for sysDescr: OID + NULL
        let mut vb1 = Vec::new();
        vb1.extend_from_slice(&encode_oid_tlv(oid_sysdescr, &Self::encode_len));
        vb1.extend_from_slice(&[0x05, 0x00]); // NULL

        // varbind for sysObjectID: OID + NULL
        let mut vb2 = Vec::new();
        vb2.extend_from_slice(&encode_oid_tlv(oid_sysobject, &Self::encode_len));
        vb2.extend_from_slice(&[0x05, 0x00]); // NULL

        // wrap each varbind in SEQUENCE and then the VarBindList as SEQUENCE of both
        let mut varbinds = Vec::new();
        for vb in &[vb1, vb2] {
            let mut seq = vec![0x30];
            seq.extend_from_slice(&Self::encode_len(vb.len()));
            seq.extend_from_slice(vb);
            varbinds.extend_from_slice(&seq);
        }
        let mut vbl = vec![0x30];
        vbl.extend_from_slice(&Self::encode_len(varbinds.len()));
        vbl.extend_from_slice(&varbinds);

        // PDU: GetRequest (0xA0) with request-id, error-status, error-index, varbindlist
        let mut pdu_body = Vec::new();
        // request-id INTEGER
        pdu_body.push(0x02);
        let req_bytes = request_id.to_be_bytes();
        let req_trim = req_bytes.iter().skip_while(|b| **b == 0).cloned().collect::<Vec<u8>>();
        let req_enc = if req_trim.is_empty() { vec![0u8] } else { req_trim };
        pdu_body.extend_from_slice(&Self::encode_len(req_enc.len()));
        pdu_body.extend_from_slice(&req_enc);

        // error-status = 0, error-index = 0
        pdu_body.extend_from_slice(&[0x02, 0x01, 0x00]);
        pdu_body.extend_from_slice(&[0x02, 0x01, 0x00]);

        // varbindlist
        pdu_body.extend_from_slice(&vbl);

        let mut pdu = vec![0xA0];
        pdu.extend_from_slice(&Self::encode_len(pdu_body.len()));
        pdu.extend_from_slice(&pdu_body);

        // SNMP message: SEQUENCE { version INTEGER(1), community OCTET STRING, pdu }
        let mut msg_body = Vec::new();
        msg_body.extend_from_slice(&[0x02, 0x01, 0x01]); // version = 1 (v2c)
        let comm_bytes = community.as_bytes();
        msg_body.push(0x04);
        msg_body.extend_from_slice(&Self::encode_len(comm_bytes.len()));
        msg_body.extend_from_slice(comm_bytes);
        msg_body.extend_from_slice(&pdu);

        let mut msg = vec![0x30];
        msg.extend_from_slice(&Self::encode_len(msg_body.len()));
        msg.extend_from_slice(&msg_body);

        msg
    }

    /// Find the varbind value for the requested OID bytes in an SNMP response.
    /// Returns the value as an owned String if found. Handles:
    /// - OCTET STRING (definite short/long and indefinite 0x80 ... 0x00 0x00)
    /// - SNMP exception tags: 0x80 (noSuchObject), 0x81 (noSuchInstance), 0x82 (endOfMibView)
    /// - INTEGER (0x02) and OBJECT IDENTIFIER (0x06) when present
/// Instrumented extractor: prints TLV walk and returns the value if found.
/// Recursively scan BER TLVs in `buf` to find `oid_bytes` and return its value as a String.
/// Supports:
/// - descending into constructed TLVs (0x30 and context-specific 0xA0..0xAF)
/// - OID (0x06) matching and reading the following value TLV
/// - value tags: 0x80/0x81/0x82 (exceptions), 0x04 (OCTET STRING short/0x81 long), 0x02 (INTEGER), 0x06 (OID)
fn extract_varbind_value_for_oid(resp: &[u8], oid_bytes: &[u8]) -> Option<String> {
    // helper to read BER length at offset `off` (off points to length byte)
    fn read_len(buf: &[u8], off: usize) -> Option<(usize, usize)> {
        if off >= buf.len() { return None; }
        let b = buf[off];
        if b & 0x80 == 0 {
            Some((b as usize, 1))
        } else {
            let n = (b & 0x7f) as usize;
            if n == 1 {
                if off + 1 >= buf.len() { return None; }
                Some((buf[off + 1] as usize, 2))
            } else {
                None
            }
        }
    }

    // recursive scanner over a slice
    fn scan_slice(slice: &[u8], oid_bytes: &[u8]) -> Option<String> {
        let mut i = 0usize;
        while i + 2 <= slice.len() {
            let tag = slice[i];
            // read length
            let len_info = read_len(slice, i + 1)?;
            let (len, hdr) = len_info;
            let content_off = i + 1 + hdr;
            if content_off + len > slice.len() { break; }

            // If this is an OID TLV, check for match
            if tag == 0x06 {
                let content = &slice[content_off .. content_off + len];
                if content == oid_bytes {
                    // Found OID; look for the next TLV after this OID within the parent slice
                    let mut j = content_off + len;
                    if j + 1 >= slice.len() { return None; }
                    let val_tag = slice[j];
                    let val_len_info = read_len(slice, j + 1)?;
                    let (val_len, val_hdr) = val_len_info;
                    let val_off = j + 1 + val_hdr;
                    if val_off + val_len > slice.len() { return None; }

                    match val_tag {
                        0x80 => return Some("noSuchObject".to_string()),
                        0x81 => return Some("noSuchInstance".to_string()),
                        0x82 => return Some("endOfMibView".to_string()),
                        0x04 => {
                            // OCTET STRING
                            let val = &slice[val_off .. val_off + val_len];
                            return std::str::from_utf8(val).map(|s| s.to_string()).ok()
                                .or_else(|| Some(format!("{:02x?}", val)));
                        }
                        0x02 => {
                            // INTEGER (big-endian)
                            let val = &slice[val_off .. val_off + val_len];
                            let mut v: i64 = 0;
                            for &b in val {
                                v = (v << 8) | (b as i64);
                            }
                            return Some(format!("{}", v));
                        }
                        0x06 => {
                            // nested OID value -> decode dotted
                            let val = &slice[val_off .. val_off + val_len];
                            if val.is_empty() { return Some(String::new()); }
                            let mut parts = Vec::new();
                            let first = val[0];
                            parts.push((first / 40).to_string());
                            parts.push((first % 40).to_string());
                            let mut idx = 1usize;
                            let mut cur: u32 = 0;
                            while idx < val.len() {
                                let byte = val[idx];
                                cur = (cur << 7) | (byte & 0x7F) as u32;
                                if (byte & 0x80) == 0 {
                                    parts.push(cur.to_string());
                                    cur = 0;
                                }
                                idx += 1;
                            }
                            return Some(parts.join("."));
                        }
                        _ => {
                            // unknown value tag: return hex
                            let val = &slice[val_off .. val_off + val_len];
                            return Some(format!("{:02x?}", val));
                        }
                    }
                }
            }

            // If this is a constructed TLV (SEQUENCE 0x30 or context-specific PDU 0xA0..0xAF), descend
            if tag == 0x30 || (tag & 0xE0) == 0xA0 {
                if let Some(found) = scan_slice(&slice[content_off .. content_off + len], oid_bytes) {
                    return Some(found);
                }
            }

            // advance to next TLV
            i = content_off + len;
        }
        None
    }

    scan_slice(resp, oid_bytes)
}





}

#[async_trait::async_trait]
impl Probe for SnmpProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        // SNMP is UDP; port parameter is respected but default probe ports should include 161
        
        let addr = format!("{}:{}", ip, port);
        let bind_addr = if ip.contains(':') { "[::]:0" } else { "0.0.0.0:0" };

        // create a Sendable RNG
        let mut rng = StdRng::from_entropy();
        let req_id: i32 = rng.gen_range(1..=0x7fffffff);
        let sock = UdpSocket::bind(bind_addr).await.ok()?;

        let req = SnmpProbe::build_snmp_get_sysdescr("public", req_id);

        // send/receive with a single retry and short backoff
        let mut attempts = 0usize;
        let max_attempts = 2usize;
        let mut last_buf: Option<Vec<u8>> = None;
        while attempts < max_attempts {
            attempts += 1;
            let _ = sock.send_to(&req, &addr).await.ok();
            let mut buf = vec![0u8; 4096];
            if let Ok(Ok((n, _peer))) = timeout(Duration::from_millis(timeout_ms), sock.recv_from(&mut buf)).await {
                buf.truncate(n);
                eprintln!("SNMP recv {} bytes from {}: preview={:02x?}", n, addr, &buf[..std::cmp::min(128, buf.len())]);
                last_buf = Some(buf);
                break;
            }
            if attempts < max_attempts {
                sleep(Duration::from_millis(150)).await;
            }
        }

        let buf = match last_buf {
            Some(b) => b,
            None => return None,
        };

        // build evidence using targeted extraction for both OIDs
        let mut evidence = String::new();
        let oid_sysdescr: &[u8] = &[0x2B,6,1,2,1,1,1,0];
        let oid_sysobject: &[u8] = &[0x2B,6,1,2,1,1,2,0];

        if let Some(s) = SnmpProbe::extract_varbind_value_for_oid(&buf, oid_sysdescr) {
            push_line(&mut evidence, "SNMP_sysDescr", &s);
        }
        if let Some(s) = SnmpProbe::extract_varbind_value_for_oid(&buf, oid_sysobject) {
            push_line(&mut evidence, "SNMP_sysObjectID", &s);
        }
        /*
        if evidence.is_empty() {
            // fallback: include a short hex preview
            push_line(&mut evidence, "SNMP_raw", &format!("{:02x?}", &buf[..std::cmp::min(128, buf.len())]));
        }*/

        // If we didn't get useful evidence (or got noSuchObject), try a GETNEXT to discover a nearby OID/value.
        let need_getnext = evidence.is_empty()
            || evidence.contains("noSuchObject")
            || evidence.contains("noSuchInstance")
            || evidence.contains("endOfMibView");

        if need_getnext {
            // Build a GETNEXT request with a new request id
            let req_id_next: i32 = rng.gen_range(1..=0x7fffffff);
            let req_next = SnmpProbe::build_snmp_getnext("public", req_id_next);

            // send/receive with same retry/backoff pattern
            let mut attempts2 = 0usize;
            let max_attempts2 = 2usize;
            let mut last_buf2: Option<Vec<u8>> = None;
            while attempts2 < max_attempts2 {
                attempts2 += 1;
                let _ = sock.send_to(&req_next, &addr).await.ok();
                let mut buf2 = vec![0u8; 4096];
                if let Ok(Ok((n2, _peer2))) = timeout(Duration::from_millis(timeout_ms), sock.recv_from(&mut buf2)).await {
                    buf2.truncate(n2);
                    eprintln!("SNMP GETNEXT recv {} bytes from {}: preview={:02x?}", n2, addr, &buf2[..std::cmp::min(128, buf2.len())]);
                    last_buf2 = Some(buf2);
                    break;
                }
                if attempts2 < max_attempts2 {
                    sleep(Duration::from_millis(150)).await;
                }
            }

         // Detailed GETNEXT varbind debug walker
            if let Some(b2) = last_buf2 {
                eprintln!("--- BEGIN GETNEXT DETAILED WALK ---");
                // helper to read BER length (short and single-byte long 0x81)
                fn read_len_local(buf: &[u8], off: usize) -> Option<(usize, usize)> {
                    if off >= buf.len() { return None; }
                    let b = buf[off];
                    if b & 0x80 == 0 {
                        Some((b as usize, 1))
                    } else {
                        let n = (b & 0x7f) as usize;
                        if n == 1 {
                            if off + 1 >= buf.len() { return None; }
                            Some((buf[off + 1] as usize, 2))
                        } else {
                            None
                        }
                    }
                }

                // Walk top-level TLVs and descend into constructed containers to find varBindList
                let mut top = 0usize;
                while top + 2 <= b2.len() {
                    let t = b2[top];
                    if top + 1 >= b2.len() { break; }
                    if let Some((top_len, top_hdr)) = read_len_local(&b2, top + 1) {
                        let content_off = top + 1 + top_hdr;
                        let content_end = content_off + top_len;
                        eprintln!("TOP TLV @{} tag=0x{:02x} len={} hdr={}", top, t, top_len, top_hdr);

                        // descend into this TLV to find varBindList sequences (0x30)
                        let mut j = content_off;
                        while j + 2 <= content_end {
                            let inner_tag = b2[j];
                            if j + 1 >= b2.len() { break; }
                            if let Some((inner_len, inner_hdr)) = read_len_local(&b2, j + 1) {
                                let inner_off = j + 1 + inner_hdr;
                                let inner_end = inner_off + inner_len;
                                eprintln!("  INNER TLV @{} tag=0x{:02x} len={} hdr={}", j, inner_tag, inner_len, inner_hdr);

                                // If this inner TLV looks like a varBindList (0x30), iterate varbinds
                                if inner_tag == 0x30 {
                                    let mut vb = inner_off;
                                    while vb + 2 <= inner_end {
                                        if b2[vb] != 0x30 { break; } // varBind should be a SEQUENCE
                                        if let Some((vb_len, vb_hdr)) = read_len_local(&b2, vb + 1) {
                                            let vb_off = vb + 1 + vb_hdr;
                                            let vb_end = vb_off + vb_len;
                                            eprintln!("    VARBIND @{} len={} off={} end={}", vb, vb_len, vb_off, vb_end);

                                            // read OID TLV
                                            if vb_off + 2 <= vb_end && b2[vb_off] == 0x06 {
                                                if let Some((oid_len, oid_hdr)) = read_len_local(&b2, vb_off + 1) {
                                                    let oid_off = vb_off + 1 + oid_hdr;
                                                    if oid_off + oid_len <= vb_end {
                                                        let oid_bytes = &b2[oid_off .. oid_off + oid_len];
                                                        eprintln!("      OID bytes @{} = {:02x?}", oid_off, oid_bytes);
                                                        // decode dotted form (simple)
                                                        if !oid_bytes.is_empty() {
                                                            let mut parts = Vec::new();
                                                            let first = oid_bytes[0];
                                                            parts.push((first / 40).to_string());
                                                            parts.push((first % 40).to_string());
                                                            let mut idx = 1usize;
                                                            let mut cur: u32 = 0;
                                                            while idx < oid_bytes.len() {
                                                                let byte = oid_bytes[idx];
                                                                cur = (cur << 7) | (byte & 0x7F) as u32;
                                                                if (byte & 0x80) == 0 {
                                                                    parts.push(cur.to_string());
                                                                    cur = 0;
                                                                }
                                                                idx += 1;
                                                            }
                                                            eprintln!("      OID dotted = {}", parts.join("."));
                                                        }
                                                        // find value TLV after OID within varbind
                                                        let mut val_pos = oid_off + oid_len;
                                                        if val_pos + 2 <= vb_end {
                                                            let val_tag = b2[val_pos];
                                                            if let Some((val_len, val_hdr)) = read_len_local(&b2, val_pos + 1) {
                                                                let val_off = val_pos + 1 + val_hdr;
                                                                if val_off + val_len <= vb_end {
                                                                    let val_bytes = &b2[val_off .. val_off + val_len];
                                                                    eprintln!("      VALUE TLV @{} tag=0x{:02x} len={} hdr={} bytes={:02x?}",
                                                                            val_pos, val_tag, val_len, val_hdr, val_bytes);
                                                                    let val_str = match val_tag {
                                                                        0x80 => "noSuchObject".to_string(),
                                                                        0x81 => "noSuchInstance".to_string(),
                                                                        0x82 => "endOfMibView".to_string(),
                                                                        0x04 => std::str::from_utf8(val_bytes).map(|s| s.to_string()).unwrap_or_else(|_| format!("{:02x?}", val_bytes)),
                                                                        0x02 => {
                                                                            let mut vv: i64 = 0;
                                                                            for &b in val_bytes { vv = (vv << 8) | (b as i64); }
                                                                            format!("{}", vv)
                                                                        }
                                                                        0x06 => {
                                                                            if val_bytes.is_empty() { "".to_string() } else {
                                                                                let mut parts = Vec::new();
                                                                                let first = val_bytes[0];
                                                                                parts.push((first / 40).to_string());
                                                                                parts.push((first % 40).to_string());
                                                                                let mut idx = 1usize;
                                                                                let mut cur: u32 = 0;
                                                                                while idx < val_bytes.len() {
                                                                                    let byte = val_bytes[idx];
                                                                                    cur = (cur << 7) | (byte & 0x7F) as u32;
                                                                                    if (byte & 0x80) == 0 {
                                                                                        parts.push(cur.to_string());
                                                                                        cur = 0;
                                                                                    }
                                                                                    idx += 1;
                                                                                }
                                                                                parts.join(".")
                                                                            }
                                                                        }
                                                                        _ => format!("{:02x?}", val_bytes),
                                                                    };
                                                                    eprintln!("      VALUE decoded = {}", val_str);
                                                                } else {
                                                                    eprintln!("      VALUE TLV overruns varbind");
                                                                }
                                                            } else {
                                                                eprintln!("      cannot read value length");
                                                            }
                                                        } else {
                                                            eprintln!("      no value TLV after OID in varbind");
                                                        }
                                                    } else {
                                                        eprintln!("      OID overruns varbind");
                                                    }
                                                } else {
                                                    eprintln!("      cannot read OID length");
                                                }
                                            } else {
                                                eprintln!("      varbind does not start with OID TLV");
                                            }

                                            vb = vb_off + vb_len;
                                            continue;
                                        } else {
                                            eprintln!("    cannot read varbind length");
                                            break;
                                        }
                                    } // end varbind loop
                                } // end if inner_tag == 0x30

                                j = inner_off + inner_len;
                                continue;
                            } else {
                                eprintln!("  cannot read inner length at {}", j + 1);
                                break;
                            }
                        } // end inner walk

                        top = content_off + top_len;
                        continue;
                    } else {
                        eprintln!("cannot read top-level length at {}", top + 1);
                        break;
                    }
                } // end top-level walk
                eprintln!("--- END GETNEXT DETAILED WALK ---");
            }

        }
        // If GETNEXT didn't produce useful results, try GETBULK (v2c only).
        let need_getbulk = need_getnext; // reuse the same condition
        if need_getbulk {
            let req_id_bulk: i32 = rng.gen_range(1..=0x7fffffff);
            // non_repeaters = 0 (treat all varbinds as repeating), max_repetitions = 8 (tunable)
            let req_bulk = SnmpProbe::build_snmp_getbulk("public", req_id_bulk, 0, 8);

            let mut attempts3 = 0usize;
            let max_attempts3 = 2usize;
            let mut last_buf3: Option<Vec<u8>> = None;
            while attempts3 < max_attempts3 {
                attempts3 += 1;
                let _ = sock.send_to(&req_bulk, &addr).await.ok();
                let mut buf3 = vec![0u8; 8192];
                if let Ok(Ok((n3, _peer3))) = timeout(Duration::from_millis(timeout_ms), sock.recv_from(&mut buf3)).await {
                    buf3.truncate(n3);
                    eprintln!("SNMP GETBULK recv {} bytes from {}: preview={:02x?}", n3, addr, &buf3[..std::cmp::min(256, buf3.len())]);
                    last_buf3 = Some(buf3);
                    break;
                }
                if attempts3 < max_attempts3 {
                    sleep(Duration::from_millis(150)).await;
                }
            }

            if let Some(b3) = last_buf3 {
                // Detailed varbind walker (debug only) — prints each varbind OID and value decoded
                eprintln!("--- BEGIN GETBULK DETAILED WALK ---");
                fn read_len_local(buf: &[u8], off: usize) -> Option<(usize, usize)> {
                    if off >= buf.len() { return None; }
                    let b = buf[off];
                    if b & 0x80 == 0 {
                        Some((b as usize, 1))
                    } else {
                        let n = (b & 0x7f) as usize;
                        if n == 1 {
                            if off + 1 >= buf.len() { return None; }
                            Some((buf[off + 1] as usize, 2))
                        } else {
                            None
                        }
                    }
                }

                let mut top = 0usize;
                while top + 2 <= b3.len() {
                    let t = b3[top];
                    if top + 1 >= b3.len() { break; }
                    if let Some((top_len, top_hdr)) = read_len_local(&b3, top + 1) {
                        let content_off = top + 1 + top_hdr;
                        let content_end = content_off + top_len;
                        eprintln!("TOP TLV @{} tag=0x{:02x} len={} hdr={}", top, t, top_len, top_hdr);

                        // descend into inner TLVs to find varBindList(s)
                        let mut j = content_off;
                        while j + 2 <= content_end {
                            let inner_tag = b3[j];
                            if j + 1 >= b3.len() { break; }
                            if let Some((inner_len, inner_hdr)) = read_len_local(&b3, j + 1) {
                                let inner_off = j + 1 + inner_hdr;
                                let inner_end = inner_off + inner_len;
                                eprintln!("  INNER TLV @{} tag=0x{:02x} len={} hdr={}", j, inner_tag, inner_len, inner_hdr);

                                if inner_tag == 0x30 {
                                    let mut vb = inner_off;
                                    while vb + 2 <= inner_end {
                                        if b3[vb] != 0x30 { break; }
                                        if let Some((vb_len, vb_hdr)) = read_len_local(&b3, vb + 1) {
                                            let vb_off = vb + 1 + vb_hdr;
                                            let vb_end = vb_off + vb_len;
                                            eprintln!("    VARBIND @{} len={} off={} end={}", vb, vb_len, vb_off, vb_end);

                                            // OID
                                            if vb_off + 2 <= vb_end && b3[vb_off] == 0x06 {
                                                if let Some((oid_len, oid_hdr)) = read_len_local(&b3, vb_off + 1) {
                                                    let oid_off = vb_off + 1 + oid_hdr;
                                                    if oid_off + oid_len <= vb_end {
                                                        let oid_bytes = &b3[oid_off .. oid_off + oid_len];
                                                        eprintln!("      OID bytes @{} = {:02x?}", oid_off, oid_bytes);
                                                        // decode dotted
                                                        if !oid_bytes.is_empty() {
                                                            let mut parts = Vec::new();
                                                            let first = oid_bytes[0];
                                                            parts.push((first / 40).to_string());
                                                            parts.push((first % 40).to_string());
                                                            let mut idx = 1usize;
                                                            let mut cur: u32 = 0;
                                                            while idx < oid_bytes.len() {
                                                                let byte = oid_bytes[idx];
                                                                cur = (cur << 7) | (byte & 0x7F) as u32;
                                                                if (byte & 0x80) == 0 {
                                                                    parts.push(cur.to_string());
                                                                    cur = 0;
                                                                }
                                                                idx += 1;
                                                            }
                                                            eprintln!("      OID dotted = {}", parts.join("."));
                                                        }

                                                        // value TLV after OID
                                                        let mut val_pos = oid_off + oid_len;
                                                        if val_pos + 2 <= vb_end {
                                                            let val_tag = b3[val_pos];
                                                            if let Some((val_len, val_hdr)) = read_len_local(&b3, val_pos + 1) {
                                                                let val_off = val_pos + 1 + val_hdr;
                                                                if val_off + val_len <= vb_end {
                                                                    let val_bytes = &b3[val_off .. val_off + val_len];
                                                                    eprintln!("      VALUE TLV @{} tag=0x{:02x} len={} hdr={} bytes={:02x?}",
                                                                            val_pos, val_tag, val_len, val_hdr, val_bytes);
                                                                    let val_str = match val_tag {
                                                                        0x80 => "noSuchObject".to_string(),
                                                                        0x81 => "noSuchInstance".to_string(),
                                                                        0x82 => "endOfMibView".to_string(),
                                                                        0x04 => std::str::from_utf8(val_bytes).map(|s| s.to_string()).unwrap_or_else(|_| format!("{:02x?}", val_bytes)),
                                                                        0x02 => {
                                                                            let mut vv: i64 = 0;
                                                                            for &b in val_bytes { vv = (vv << 8) | (b as i64); }
                                                                            format!("{}", vv)
                                                                        }
                                                                        0x06 => {
                                                                            if val_bytes.is_empty() { "".to_string() } else {
                                                                                let mut parts = Vec::new();
                                                                                let first = val_bytes[0];
                                                                                parts.push((first / 40).to_string());
                                                                                parts.push((first % 40).to_string());
                                                                                let mut idx = 1usize;
                                                                                let mut cur: u32 = 0;
                                                                                while idx < val_bytes.len() {
                                                                                    let byte = val_bytes[idx];
                                                                                    cur = (cur << 7) | (byte & 0x7F) as u32;
                                                                                    if (byte & 0x80) == 0 {
                                                                                        parts.push(cur.to_string());
                                                                                        cur = 0;
                                                                                    }
                                                                                    idx += 1;
                                                                                }
                                                                                parts.join(".")
                                                                            }
                                                                        }
                                                                        _ => format!("{:02x?}", val_bytes),
                                                                    };
                                                                    eprintln!("      VALUE decoded = {}", val_str);

                                                                    // append to evidence
                                                                    push_line(&mut evidence, "SNMP_getbulk_oid", &format!("{:02x?}", oid_bytes));
                                                                    push_line(&mut evidence, "SNMP_getbulk_value", &val_str);
                                                                } else {
                                                                    eprintln!("      VALUE TLV overruns varbind");
                                                                }
                                                            } else {
                                                                eprintln!("      cannot read value length");
                                                            }
                                                        } else {
                                                            eprintln!("      no value TLV after OID in varbind");
                                                        }
                                                    } else {
                                                        eprintln!("      OID overruns varbind");
                                                    }
                                                } else {
                                                    eprintln!("      cannot read OID length");
                                                }
                                            } else {
                                                eprintln!("      varbind does not start with OID TLV");
                                            }

                                            vb = vb_off + vb_len;
                                            continue;
                                        } else {
                                            eprintln!("    cannot read varbind length");
                                            break;
                                        }
                                    } // end varbind loop
                                } // end if inner_tag == 0x30

                                j = inner_off + inner_len;
                                continue;
                            } else {
                                eprintln!("  cannot read inner length at {}", j + 1);
                                break;
                            }
                        } // end inner walk

                        top = content_off + top_len;
                        continue;
                    } else {
                        eprintln!("cannot read top-level length at {}", top + 1);
                        break;
                    }
                } // end top-level walk
                eprintln!("--- END GETBULK DETAILED WALK ---");
            }
        }


        Some(ServiceFingerprint::from_banner(ip, port, "snmp", evidence))
    }

    fn ports(&self) -> Vec<u16> { vec![161] }
    fn name(&self) -> &'static str { "snmp" }
}
