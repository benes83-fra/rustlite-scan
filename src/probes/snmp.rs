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
    fn extract_varbind_value_for_oid(resp: &[u8], oid_bytes: &[u8]) -> Option<String> {
        let mut i = 0usize;
        while i + 2 < resp.len() {
            let tag = resp[i];
            let len = resp[i + 1] as usize;
            if i + 2 + len > resp.len() { break; }

            if tag == 0x06 {
                // OID tag found; compare contents
                let content = &resp[i + 2 .. i + 2 + len];
                if content == oid_bytes {
                    // Found the OID; now scan forward for the next value TLV
                    let mut j = i + 2 + len;
                    while j + 1 < resp.len() {
                        let t = resp[j];
                        // ensure we have at least a length byte
                        if j + 1 >= resp.len() { break; }
                        let len_byte = resp[j + 1];

                        // Handle SNMP exception tags (application-specific in SNMP)
                        match t {
                            0x80 => return Some("noSuchObject".to_string()),
                            0x81 => return Some("noSuchInstance".to_string()),
                            0x82 => return Some("endOfMibView".to_string()),
                            0x04 => {
                                // OCTET STRING
                                if len_byte == 0x80 {
                                    // Indefinite length: read until 0x00 0x00
                                    let start = j + 2;
                                    let mut k = start;
                                    while k + 1 < resp.len() {
                                        if resp[k] == 0x00 && resp[k + 1] == 0x00 {
                                            let val = &resp[start .. k];
                                            return std::str::from_utf8(val).map(|s| s.to_string()).ok()
                                                .or_else(|| Some(format!("{:02x?}", val)));
                                        }
                                        k += 1;
                                    }
                                    return None;
                                } else if (len_byte & 0x80) == 0 {
                                    // short definite length
                                    let val_off = j + 2;
                                    let val_len = len_byte as usize;
                                    if val_off + val_len <= resp.len() {
                                        let val = &resp[val_off .. val_off + val_len];
                                        return std::str::from_utf8(val).map(|s| s.to_string()).ok()
                                            .or_else(|| Some(format!("{:02x?}", val)));
                                    } else {
                                        return None;
                                    }
                                } else {
                                    // long definite length (support single extra length byte)
                                    let n = (len_byte & 0x7f) as usize;
                                    if n == 1 {
                                        if j + 2 >= resp.len() { return None; }
                                        let val_len = resp[j + 2] as usize;
                                        let val_off = j + 3;
                                        if val_off + val_len <= resp.len() {
                                            let val = &resp[val_off .. val_off + val_len];
                                            return std::str::from_utf8(val).map(|s| s.to_string()).ok()
                                                .or_else(|| Some(format!("{:02x?}", val)));
                                        } else {
                                            return None;
                                        }
                                    } else {
                                        return None;
                                    }
                                }
                            }
                            0x02 => {
                                // INTEGER
                                if (len_byte & 0x80) == 0 {
                                    let val_off = j + 2;
                                    let val_len = len_byte as usize;
                                    if val_off + val_len <= resp.len() {
                                        let val = &resp[val_off .. val_off + val_len];
                                        // decode big-endian signed integer (small sizes)
                                        let mut v: i64 = 0;
                                        for &b in val {
                                            v = (v << 8) | (b as i64);
                                        }
                                        return Some(format!("{}", v));
                                    }
                                }
                                return None;
                            }
                            0x06 => {
                                // nested OID value (rare), parse and return dotted form
                                if (len_byte & 0x80) == 0 {
                                    let val_off = j + 2;
                                    let val_len = len_byte as usize;
                                    if val_off + val_len <= resp.len() {
                                        let val = &resp[val_off .. val_off + val_len];
                                        // simple OID decode: first byte = 40*X + Y
                                        if !val.is_empty() {
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
                                    }
                                }
                                return None;
                            }
                            _ => {
                                // Unknown tag: try to skip it safely
                                let skip_len = if (len_byte & 0x80) == 0 {
                                    2 + (len_byte as usize)
                                } else {
                                    // support single extra length byte
                                    if (len_byte & 0x7f) as usize == 1 {
                                        let l = resp.get(j + 2).cloned().unwrap_or(0) as usize;
                                        3 + l
                                    } else {
                                        // unknown multi-byte length: abort scanning
                                        break;
                                    }
                                };
                                j += skip_len;
                                continue;
                            }
                        }
                    }
                    // found OID but not its value
                    return None;
                }
            }

            // skip this TLV and continue scanning
            i += 2 + len;
        }
        None
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
        if evidence.is_empty() {
            // fallback: include a short hex preview
            push_line(&mut evidence, "SNMP_raw", &format!("{:02x?}", &buf[..std::cmp::min(128, buf.len())]));
        }

        Some(ServiceFingerprint::from_banner(ip, port, "snmp", evidence))
    }

    fn ports(&self) -> Vec<u16> { vec![161] }
    fn name(&self) -> &'static str { "snmp" }
}
