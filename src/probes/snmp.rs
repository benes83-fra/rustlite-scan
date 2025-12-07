
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use crate::service::ServiceFingerprint;
use super::Probe;
use crate::probes::helper::push_line; // reuse your existing push_line helper

/// SNMP probe that requests sysDescr.0 via SNMPv2c community "public"
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

    fn build_snmp_get_sysdescr(community: &str, request_id: i32) -> Vec<u8> {
        // OID encoding for 1.3.6.1.2.1.1.1.0 -> 0x2B,6,1,2,1,1,1,0
        let oid_body: Vec<u8> = vec![0x2B, 6, 1, 2, 1, 1, 1, 0];

        // VarBind: OID + NULL
        let mut varbind = Vec::new();
        varbind.push(0x06); // OID tag
        varbind.extend_from_slice(&Self::encode_len(oid_body.len()));
        varbind.extend_from_slice(&oid_body);
        varbind.extend_from_slice(&[0x05, 0x00]); // NULL value

        // wrap varbind in SEQUENCE
        let mut varbind_seq = vec![0x30];
        varbind_seq.extend_from_slice(&Self::encode_len(varbind.len()));
        varbind_seq.extend_from_slice(&varbind);

        // VarBindList: SEQUENCE of varbind_seq
        let mut vbl = vec![0x30];
        vbl.extend_from_slice(&Self::encode_len(varbind_seq.len()));
        vbl.extend_from_slice(&varbind_seq);

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

    fn parse_snmp_sysdescr(resp: &[u8]) -> Option<String> {
        let oid_bytes: &[u8] = &[0x2B, 6, 1, 2, 1, 1, 1, 0];
        if let Some(pos) = resp.windows(oid_bytes.len()).position(|w| w == oid_bytes) {
            for j in pos + oid_bytes.len()..std::cmp::min(resp.len(), pos + oid_bytes.len() + 512) {
                if resp[j] == 0x04 {
                    if j + 1 >= resp.len() { break; }
                    let len_byte = resp[j + 1] as usize;
                    let (val_off, val_len) = if len_byte & 0x80 == 0 {
                        (j + 2, len_byte)
                    } else {
                        if j + 2 >= resp.len() { break; }
                        let n = (len_byte & 0x7f) as usize;
                        if n == 1 {
                            let l = resp[j + 2] as usize;
                            (j + 3, l)
                        } else {
                            break;
                        }
                    };
                    if val_off + val_len <= resp.len() {
                        let val = &resp[val_off..val_off + val_len];
                        if let Ok(s) = std::str::from_utf8(val) {
                            return Some(s.to_string());
                        } else {
                            return Some(format!("{:02x?}", val));
                        }
                    }
                }
            }
        }

        // fallback: first OCTET STRING in packet
        for i in 0..resp.len() {
            if resp[i] == 0x04 {
                if i + 1 >= resp.len() { break; }
                let len_byte = resp[i + 1] as usize;
                let (val_off, val_len) = if len_byte & 0x80 == 0 {
                    (i + 2, len_byte)
                } else {
                    if i + 2 >= resp.len() { break; }
                    let n = (len_byte & 0x7f) as usize;
                    if n == 1 {
                        let l = resp[i + 2] as usize;
                        (i + 3, l)
                    } else {
                        break;
                    }
                };
                if val_off + val_len <= resp.len() {
                    let val = &resp[val_off..val_off + val_len];
                    if let Ok(s) = std::str::from_utf8(val) {
                        return Some(s.to_string());
                    } else {
                        return Some(format!("{:02x?}", val));
                    }
                }
            }
        }

        None
    }
}

#[async_trait::async_trait]
impl Probe for SnmpProbe {
   async  fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        // SNMP is UDP; port parameter is respected but default probe ports should include 161
        let addr = format!("{}:{}", ip, port);
        let bind_addr = if ip.contains(':') { "[::]:0" } else { "0.0.0.0:0" };

        

        // create a Sendable RNG
        let mut rng = StdRng::from_entropy();
        let req_id: i32 = rng.gen_range(1..=0x7fffffff);
        let sock = UdpSocket::bind(bind_addr).await.ok()?;

        // random request id
      
        let req = SnmpProbe::build_snmp_get_sysdescr("public", req_id);

        // send request
        if sock.send_to(&req, &addr).await.is_err() {
            return None;
        }

        // receive with timeout
        let mut buf = vec![0u8; 4096];
        let recv = timeout(Duration::from_millis(timeout_ms), sock.recv_from(&mut buf)).await;
        let (n, _peer) = match recv {
            Ok(Ok((n, p))) => (n, p),
            _ => return None,
        };
        buf.truncate(n);

        // build evidence
        let mut evidence = String::new();
        if let Some(s) = SnmpProbe::parse_snmp_sysdescr(&buf) {
            push_line(&mut evidence, "SNMP_sysDescr", &s);
        } else {
            // include a short hex preview
            let preview = &buf[..std::cmp::min(128, buf.len())];
            push_line(&mut evidence, "SNMP_raw", &format!("{:02x?}", preview));
        }

        Some(ServiceFingerprint::from_banner(ip, port, "snmp", evidence))
    }

    fn ports(&self) -> Vec<u16> { vec![161] }
    fn name(&self) -> &'static str { "snmp" }
}
