use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration, sleep};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use crate::service::ServiceFingerprint;
use super::Probe;
use crate::probes::helper::push_line;

/// SNMP probe that requests sysDescr.0 and sysObjectID.0 via SNMPv2c community "public"
pub struct SnmpProbe;

// Toggle debug prints
const DEBUG: bool = true;

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

    /// Build a generic GetNext PDU (A1) using the same varbind layout as build_snmp_get_sysdescr
    fn build_snmp_getnext(community: &str, request_id: i32) -> Vec<u8> {
        // reuse the same OIDs as in build_snmp_get_sysdescr
        let oid_sysdescr: &[u8] = &[0x2B, 6, 1, 2, 1, 1, 1, 0];
        let oid_sysobject: &[u8] = &[0x2B, 6, 1, 2, 1, 1, 2, 0];

        fn encode_oid_tlv(oid_body: &[u8], encode_len: &dyn Fn(usize) -> Vec<u8>) -> Vec<u8> {
            let mut v = vec![0x06];
            v.extend_from_slice(&encode_len(oid_body.len()));
            v.extend_from_slice(oid_body);
            v
        }

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

        let mut pdu_body = Vec::new();
        pdu_body.push(0x02);
        let req_bytes = request_id.to_be_bytes();
        let req_trim = req_bytes.iter().skip_while(|b| **b == 0).cloned().collect::<Vec<u8>>();
        let req_enc = if req_trim.is_empty() { vec![0u8] } else { req_trim };
        pdu_body.extend_from_slice(&Self::encode_len(req_enc.len()));
        pdu_body.extend_from_slice(&req_enc);

        // error-status = 0, error-index = 0
        pdu_body.extend_from_slice(&[0x02, 0x01, 0x00]);
        pdu_body.extend_from_slice(&[0x02, 0x01, 0x00]);

        pdu_body.extend_from_slice(&vbl);

        let mut pdu = vec![0xA1];
        pdu.extend_from_slice(&Self::encode_len(pdu_body.len()));
        pdu.extend_from_slice(&pdu_body);

        let mut msg_body = Vec::new();
        msg_body.extend_from_slice(&[0x02, 0x01, 0x01]);
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

    /// Build a minimal GETBULK (A5) using the same varbinds; non_repeaters and max_repetitions are encoded as integers.
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

        // helper to encode INTEGER TLV (small)
        fn encode_int_tlv(v: i32) -> Vec<u8> {
            let bytes = v.to_be_bytes();
            let trimmed = bytes.iter().skip_while(|b| **b == 0).cloned().collect::<Vec<u8>>();
            let enc = if trimmed.is_empty() { vec![0u8] } else { trimmed };
            let mut out = vec![0x02];
            out.extend_from_slice(&SnmpProbe::encode_len(enc.len()));
            out.extend_from_slice(&enc);
            out
        }

        let mut pdu_body = Vec::new();
        // request-id
        pdu_body.extend_from_slice(&encode_int_tlv(request_id));
        // non-repeaters
        pdu_body.extend_from_slice(&encode_int_tlv(non_repeaters));
        // max-repetitions
        pdu_body.extend_from_slice(&encode_int_tlv(max_repetitions));
        // varbindlist
        pdu_body.extend_from_slice(&vbl);

        let mut pdu = vec![0xA5];
        pdu.extend_from_slice(&Self::encode_len(pdu_body.len()));
        pdu.extend_from_slice(&pdu_body);

        let mut msg_body = Vec::new();
        msg_body.extend_from_slice(&[0x02, 0x01, 0x01]);
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

    /// Read a BER length at offset `off` (off points to length byte)
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

    /// Extract a varbind value for a given OID by recursively scanning constructed TLVs.
    fn extract_varbind_value_for_oid(resp: &[u8], oid_bytes: &[u8]) -> Option<String> {
        // recursive scanner over a slice
        fn scan_slice(slice: &[u8], oid_bytes: &[u8]) -> Option<String> {
            let mut i = 0usize;
            while i + 2 <= slice.len() {
                let tag = slice[i];
                let len_info = SnmpProbe::read_len(slice, i + 1)?;
                let (len, hdr) = len_info;
                let content_off = i + 1 + hdr;
                if content_off + len > slice.len() { break; }

                // If this is an OID TLV, check for match
                if tag == 0x06 {
                    let content = &slice[content_off .. content_off + len];
                    if content == oid_bytes {
                        // Found OID; look for the next TLV after this OID within the parent slice
                        let  j = content_off + len;
                        if j + 1 >= slice.len() { return None; }
                        let val_tag = slice[j];
                        let val_len_info = SnmpProbe::read_len(slice, j + 1)?;
                        let (val_len, val_hdr) = val_len_info;
                        let val_off = j + 1 + val_hdr;
                        if val_off + val_len > slice.len() { return None; }

                        match val_tag {
                            0x80 => return Some("noSuchObject".to_string()),
                            0x81 => return Some("noSuchInstance".to_string()),
                            0x82 => return Some("endOfMibView".to_string()),
                            0x04 => {
                                let val = &slice[val_off .. val_off + val_len];
                                return std::str::from_utf8(val).map(|s| s.to_string()).ok()
                                    .or_else(|| Some(format!("{:02x?}", val)));
                            }
                            0x02 => {
                                let val = &slice[val_off .. val_off + val_len];
                                let mut v: i64 = 0;
                                for &b in val {
                                    v = (v << 8) | (b as i64);
                                }
                                return Some(format!("{}", v));
                            }
                            0x06 => {
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
                                let val = &slice[val_off .. val_off + val_len];
                                return Some(format!("{:02x?}", val));
                            }
                        }
                    }
                }

                // descend into constructed TLVs
                if tag == 0x30 || (tag & 0xE0) == 0xA0 {
                    if let Some(found) = scan_slice(&slice[content_off .. content_off + len], oid_bytes) {
                        return Some(found);
                    }
                }

                i = content_off + len;
            }
            None
        }

        scan_slice(resp, oid_bytes)
    }

    /// Single helper: send a request and wait for a response with retries. Returns received bytes or None.
    async fn send_and_recv(sock: &UdpSocket, addr: &str, req: &[u8], timeout_ms: u64, attempts: usize) -> Option<Vec<u8>> {
        for attempt in 1..=attempts {
            if DEBUG { eprintln!("SNMP send attempt {} -> {} ({} bytes): {:02x?}", attempt, addr, req.len(), req); }
            if let Err(e) = sock.send_to(req, addr).await.map_err(|e| e) {
                eprintln!("SNMP send error: {}", e);
            }

            let mut buf = vec![0u8; 8192];
            match timeout(Duration::from_millis(timeout_ms.max(2000)), sock.recv_from(&mut buf)).await {
                Ok(Ok((n, peer))) => {
                    buf.truncate(n);
                    if DEBUG { eprintln!("SNMP recv {} bytes from {}: preview={:02x?}", n, peer, &buf[..std::cmp::min(128, buf.len())]); }
                    return Some(buf);
                }
                Ok(Err(e)) => {
                    eprintln!("SNMP recv_from error: {}", e);
                    return None;
                }
                Err(_) => {
                    if DEBUG { eprintln!("SNMP recv timeout on attempt {}", attempt); }
                }
            }

            if attempt < attempts {
                sleep(Duration::from_millis(150)).await;
            }
        }
        None
    }
}

#[async_trait::async_trait]
impl Probe for SnmpProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let addr = format!("{}:{}", ip, port);
        let bind_addr = if ip.contains(':') { "[::]:0" } else { "0.0.0.0:0" };

        let mut rng = StdRng::from_entropy();
        let req_id: i32 = rng.gen_range(1..=0x7fffffff);
        let sock = UdpSocket::bind(bind_addr).await.ok()?;

        // Build and send the original GET request (kept intact)
        let req = SnmpProbe::build_snmp_get_sysdescr("public", req_id);
        let resp = SnmpProbe::send_and_recv(&sock, &addr, &req, timeout_ms, 2).await?;
        let mut evidence = String::new();

        // targeted extraction for both OIDs
        let oid_sysdescr: &[u8] = &[0x2B,6,1,2,1,1,1,0];
        let oid_sysobject: &[u8] = &[0x2B,6,1,2,1,1,2,0];

        if let Some(s) = SnmpProbe::extract_varbind_value_for_oid(&resp, oid_sysdescr) {
            push_line(&mut evidence, "SNMP_sysDescr", &s);
        }
        if let Some(s) = SnmpProbe::extract_varbind_value_for_oid(&resp, oid_sysobject) {
            push_line(&mut evidence, "SNMP_sysObjectID", &s);
        }

        // decide if we should try GETNEXT / GETBULK
        let need_more = evidence.is_empty()
            || evidence.contains("noSuchObject")
            || evidence.contains("noSuchInstance")
            || evidence.contains("endOfMibView");

        if need_more {
            // GETNEXT
            let req_id_next: i32 = rng.gen_range(1..=0x7fffffff);
            let req_next = SnmpProbe::build_snmp_getnext("public", req_id_next);
            if let Some(resp2) = SnmpProbe::send_and_recv(&sock, &addr, &req_next, timeout_ms, 2).await {
                // scan for any OID/value pairs by reusing the extractor on common OIDs
                if let Some(v) = SnmpProbe::extract_varbind_value_for_oid(&resp2, oid_sysdescr) {
                    push_line(&mut evidence, "SNMP_getnext_sysDescr", &v);
                }
                if let Some(v) = SnmpProbe::extract_varbind_value_for_oid(&resp2, oid_sysobject) {
                    push_line(&mut evidence, "SNMP_getnext_sysObjectID", &v);
                }
            }
        }

        // GETBULK fallback if still nothing useful
        let need_bulk = evidence.is_empty()
            || evidence.contains("noSuchObject")
            || evidence.contains("noSuchInstance")
            || evidence.contains("endOfMibView");

        if need_bulk {
            let req_id_bulk: i32 = rng.gen_range(1..=0x7fffffff);
            let req_bulk = SnmpProbe::build_snmp_getbulk("public", req_id_bulk, 0, 8);
            if let Some(resp3) = SnmpProbe::send_and_recv(&sock, &addr, &req_bulk, timeout_ms, 2).await {
                // try to extract the same OIDs (or record raw if exceptions)
                if let Some(v) = SnmpProbe::extract_varbind_value_for_oid(&resp3, oid_sysdescr) {
                    push_line(&mut evidence, "SNMP_getbulk_sysDescr", &v);
                }
                if let Some(v) = SnmpProbe::extract_varbind_value_for_oid(&resp3, oid_sysobject) {
                    push_line(&mut evidence, "SNMP_getbulk_sysObjectID", &v);
                }
            }
        }

        if evidence.is_empty() {
            // keep a short raw preview for debugging
            push_line(&mut evidence, "SNMP_raw", &format!("{:02x?}", &resp[..std::cmp::min(128, resp.len())]));
        }

        Some(ServiceFingerprint::from_banner(ip, port, "snmp", evidence))
    }

    fn ports(&self) -> Vec<u16> { vec![161] }
    fn name(&self) -> &'static str { "snmp" }
}
