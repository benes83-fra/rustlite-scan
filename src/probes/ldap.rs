use super::Probe;
use crate::probes::tls::fingerprint_tls;
use crate::probes::ProbeContext;
use crate::service::ServiceFingerprint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Duration;

use crate::probes::helper::{
    connect_with_timeout, ldap_result_text, send_and_read, upgrade_to_tls,
};

pub struct LdapProbe;

#[async_trait::async_trait]
impl Probe for LdapProbe {
    async fn probe_with_ctx(
        &self,
        ip: &str,
        port: u16,
        ctx: ProbeContext,
    ) -> Option<ServiceFingerprint> {
        let timeout_ms = ctx
            .get("timeout_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(2000);
        self.probe(ip, port, timeout_ms).await
    }
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        // Connect once (reuse for bind -> RootDSE -> StartTLS)
        let mut stream = connect_with_timeout(ip, port, timeout_ms).await?;

        let mut evidence = String::new();

        // Optional initial read (some servers send nothing)
        if let Some(tmp) = {
            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    buf.truncate(n);
                    Some(buf)
                }
                _ => None,
            }
        } {
            // keep a short preview
            if !tmp.is_empty() {
                let preview = &tmp[..std::cmp::min(64, tmp.len())];
                evidence.push_str(&format!("initial_raw: {:02x?}\n", preview));
            }
        }

        // 1) Anonymous bind (messageID=1)
        let bind_request: Vec<u8> = vec![
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
        ];

        if let Some(resp) = send_and_read(&mut stream, &bind_request, 500, 1000).await {
            // decode numeric code if present
            if let Some(pos) = resp.iter().position(|&b| b == 0x61) {
                let code = resp.get(pos + 2).copied().unwrap_or(255);
                let text = ldap_result_text(code);
                if !evidence.is_empty() {
                    evidence.push('\n');
                }
                evidence.push_str(&format!(
                    "LDAP_bind_response: result_code={} ({})",
                    code, text
                ));
            } else {
                if !evidence.is_empty() {
                    evidence.push('\n');
                }
                evidence.push_str(&format!(
                    "LDAP_bind_raw: {:02x?}",
                    &resp[..std::cmp::min(64, resp.len())]
                ));
            }
        } else {
            // no bind response — record marker but continue
            if !evidence.is_empty() {
                evidence.push('\n');
            }
            evidence.push_str("LDAP_bind_response: <no response>");
        }

        // 2) RootDSE search (messageID=2)
        let attrs = [
            "namingContexts",
            "supportedLDAPVersion",
            "vendorName",
            "vendorVersion",
            "supportedExtension",
            "supportedControl",
            "supportedSASLMechanisms",
            "subschemaSubentry",
            "altServer",
        ];
        let req = build_rootdse_search(2, &attrs);
        let rootdse_resp_bytes_opt = send_and_read(&mut stream, &req, 500, 1000).await;

        if let Some(rootdse_resp_bytes) = rootdse_resp_bytes_opt.clone() {
            let decoded = decode_rootdse_response(&rootdse_resp_bytes, &attrs);
            if !evidence.is_empty() {
                evidence.push('\n');
            }
            evidence.push_str(&decoded);

            // Follow altServer referrals (limit to 3)
            follow_altservers_and_append(&rootdse_resp_bytes, &attrs, &mut evidence, 3, timeout_ms)
                .await;
        } else {
            if !evidence.is_empty() {
                evidence.push('\n');
            }
            evidence.push_str("RootDSE: <no response>");
        }

        // 3) StartTLS ExtendedRequest (messageID=3)
        let starttls_request: Vec<u8> = vec![
            0x30, 0x11, 0x02, 0x01, 0x03, 0x77, 0x0c, 0x80, 0x0b,
            // OID 1.3.6.1.4.1.1466.20037
            0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x31, 0x34,
            0x36, 0x36, 0x2e, 0x32, 0x30, 0x30, 0x33, 0x37,
        ];

        if let Some(resp) = send_and_read(&mut stream, &starttls_request, 500, 1000).await {
            // append StartTLS response decode
            let dec = decode_ldap_response(&resp);
            if !evidence.is_empty() {
                evidence.push('\n');
            }
            evidence.push_str(&dec);

            // If ExtendedResponse tag present, attempt TLS upgrade on same stream
            if resp.iter().any(|&b| b == 0x78) {
                // upgrade_to_tls consumes the TcpStream
                match upgrade_to_tls(stream, ip).await {
                    Ok(tls_stream) => {
                        // fingerprint_tls returns Option<ServiceFingerprint> or similar
                        if let Some(fp) =
                            fingerprint_tls(ip, port, "ldap", evidence.clone(), tls_stream).await
                        {
                            if let Some(ev) = fp.evidence {
                                if !evidence.is_empty() {
                                    evidence.push('\n');
                                }
                                evidence.push_str(&ev);
                            }
                        }
                        return Some(ServiceFingerprint::from_banner(ip, port, "ldap", evidence));
                    }
                    Err(_) => {
                        // TLS upgrade failed — return accumulated evidence
                        return Some(ServiceFingerprint::from_banner(ip, port, "ldap", evidence));
                    }
                }
            }
        } else {
            if !evidence.is_empty() {
                evidence.push('\n');
            }
            evidence.push_str("StartTLS: <no response>");
        }

        // No TLS upgrade — return accumulated evidence
        Some(ServiceFingerprint::from_banner(ip, port, "ldap", evidence))
    }

    fn ports(&self) -> Vec<u16> {
        vec![389, 636]
    }
    fn name(&self) -> &'static str {
        "ldap"
    }
}

fn decode_ldap_response(data: &[u8]) -> String {
    if let Some(pos) = data.iter().position(|&b| b == 0x61) {
        let code = data.get(pos + 2).copied().unwrap_or(255);
        format!("LDAP_bind_response: result_code={}", code)
    } else if let Some(_pos) = data.iter().position(|&b| b == 0x78) {
        "LDAP_extended_response (StartTLS)".to_string()
    } else {
        format!("LDAP_raw: {:02x?}", &data[..std::cmp::min(32, data.len())])
    }
}

fn encode_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        // extend if you need >255, but for our attribute lists this is enough
        panic!("length too large");
    }
}

/// Build an LDAP SearchRequest (base object "") for the given attributes.
/// message_id is the LDAP message ID (e.g., 3).
pub fn build_rootdse_search(message_id: u8, attrs: &[&str]) -> Vec<u8> {
    // messageID
    let msg = vec![0x02, 0x01, message_id];

    // Build attributes sequence payload (each attribute is an OCTET STRING)
    let mut attrs_payload = Vec::new();
    for &a in attrs {
        let bytes = a.as_bytes();
        attrs_payload.push(0x04); // OCTET STRING
        attrs_payload.extend_from_slice(&encode_len(bytes.len()));
        attrs_payload.extend_from_slice(bytes);
    }
    // wrap attributes in SEQUENCE (0x30)
    let mut attrs_seq = vec![0x30];
    attrs_seq.extend_from_slice(&encode_len(attrs_payload.len()));
    attrs_seq.extend_from_slice(&attrs_payload);

    // Build present filter for objectClass: tag 0x87
    let oc = b"objectClass";
    let mut filter = vec![0x87];
    filter.extend_from_slice(&encode_len(oc.len()));
    filter.extend_from_slice(oc);

    // Build the SearchRequest body (APPLICATION 3 -> tag 0x63)
    // baseObject: OCTET STRING "" -> 0x04 0x00
    let mut search_body = Vec::new();
    search_body.extend_from_slice(&[0x04, 0x00]); // baseObject ""
    search_body.extend_from_slice(&[0x0a, 0x01, 0x00]); // scope ENUMERATED 0 (base)
    search_body.extend_from_slice(&[0x0a, 0x01, 0x00]); // deref ENUMERATED 0
    search_body.extend_from_slice(&[0x02, 0x01, 0x00]); // sizeLimit INTEGER 0
    search_body.extend_from_slice(&[0x02, 0x01, 0x00]); // timeLimit INTEGER 0
    search_body.extend_from_slice(&[0x01, 0x01, 0x00]); // typesOnly BOOLEAN FALSE
    search_body.extend_from_slice(&filter); // filter present (objectClass)
    search_body.extend_from_slice(&attrs_seq); // attributes sequence

    // Wrap search_body in APPLICATION 3 tag (0x63)
    let mut app3 = vec![0x63];
    app3.extend_from_slice(&encode_len(search_body.len()));
    app3.extend_from_slice(&search_body);

    // Now wrap message: SEQUENCE { messageID, searchRequest }
    let mut full = vec![0x30];
    let total_len = msg.len() + app3.len();
    full.extend_from_slice(&encode_len(total_len));
    full.extend_from_slice(&msg);
    full.extend_from_slice(&app3);

    full
}

/// Heuristic parser: look for attribute names and extract following OCTET STRING values.
/// Returns a readable multi-line string with attribute -> values.
pub fn decode_rootdse_response(resp: &[u8], attrs: &[&str]) -> String {
    let mut out = String::new();

    for &attr in attrs {
        let needle = attr.as_bytes();
        if let Some(pos) = resp.windows(needle.len()).position(|w| w == needle) {
            // After the attribute name in LDAP SearchResultEntry, the value is usually encoded as:
            // 0x04 <len> <value>  (OCTET STRING)
            // We'll scan forward from pos for the next 0x04 tag and read its length.
            let i = pos + needle.len();
            // scan forward up to some bytes to find 0x04
            let mut found = false;
            for j in i..std::cmp::min(resp.len(), i + 200) {
                if resp[j] == 0x04 {
                    // read length byte(s)
                    if j + 1 >= resp.len() {
                        break;
                    }
                    let len_byte = resp[j + 1] as usize;
                    let (val_off, val_len) = if len_byte & 0x80 == 0 {
                        (j + 2, len_byte)
                    } else {
                        // long form (support single extra length byte)
                        if j + 2 >= resp.len() {
                            break;
                        }
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
                        // try to interpret as UTF-8, else hex
                        let val_str = match std::str::from_utf8(val) {
                            Ok(s) => s.to_string(),
                            Err(_) => format!("{:02x?}", val),
                        };
                        if !out.is_empty() {
                            out.push('\n');
                        }
                        out.push_str(&format!("{}: {}", attr, val_str));
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(&format!("{}: <present but value not parsed>", attr));
            }
        } else {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&format!("{}: <not present>", attr));
        }
    }

    out
}

/// Scan an LDAP SearchResultEntry/RootDSE response for altServer attribute values.
/// Returns a Vec of strings (each value is typically an LDAP URL like "ldap://host:389").
pub fn extract_altservers(resp: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let needle = b"altServer";
    if let Some(mut pos) = resp.windows(needle.len()).position(|w| w == needle) {
        // Walk through all occurrences
        while pos < resp.len() {
            if resp
                .windows(needle.len())
                .position(|w| w == needle)
                .is_none()
            {
                break;
            }
            // find next occurrence starting at pos
            if let Some(p) = resp[pos..].windows(needle.len()).position(|w| w == needle) {
                pos += p;
            } else {
                break;
            }

            // scan forward for next OCTET STRING tag 0x04
            let mut found = false;
            for j in pos + needle.len()..std::cmp::min(resp.len(), pos + needle.len() + 512) {
                if resp[j] == 0x04 {
                    // read length byte(s)
                    if j + 1 >= resp.len() {
                        break;
                    }
                    let len_byte = resp[j + 1] as usize;
                    let (val_off, val_len) = if len_byte & 0x80 == 0 {
                        (j + 2, len_byte)
                    } else {
                        // support single extra length byte
                        if j + 2 >= resp.len() {
                            break;
                        }
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
                            // altServer may contain multiple URLs separated by spaces or commas
                            for token in s.split(|c: char| c == ' ' || c == ',') {
                                let t = token.trim();
                                if !t.is_empty() {
                                    out.push(t.to_string());
                                }
                            }
                        } else {
                            out.push(format!("{:02x?}", val));
                        }
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                break;
            }
            pos += needle.len();
        }
    }
    out
}

/// Follow up to `max_follow` altServer URIs found in `rootdse_resp`.
/// For each reachable referral, perform a RootDSE search and append decoded lines to `evidence`.
pub async fn follow_altservers_and_append(
    rootdse_resp: &[u8],
    attrs: &[&str],
    evidence: &mut String,
    max_follow: usize,
    timeout_ms: u64,
) {
    let urls = extract_altservers(rootdse_resp);
    if urls.is_empty() {
        return;
    }

    let mut followed = 0usize;
    for url in urls {
        if followed >= max_follow {
            break;
        }
        // Basic parse: expect ldap://host[:port] or ldaps://host[:port]
        let (scheme, hostport) = if let Some(rest) = url.strip_prefix("ldap://") {
            ("ldap", rest)
        } else if let Some(rest) = url.strip_prefix("ldaps://") {
            ("ldaps", rest)
        } else {
            // skip unknown schemes
            continue;
        };

        // split host and optional port
        let mut host = hostport;
        let mut port = if scheme == "ldaps" { 636 } else { 389 };
        if let Some(idx) = hostport.rfind(':') {
            // crude check: if there's a colon and the suffix is digits, treat as port
            if hostport[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
                if let Ok(p) = hostport[idx + 1..].parse::<u16>() {
                    port = p;
                    host = &hostport[..idx];
                }
            }
        }

        // attempt connect
        let addr = format!("{}:{}", host, port);
        match tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr))
            .await
        {
            Ok(Ok(mut stream)) => {
                // build RootDSE search (message id 1 is fine for a fresh connection)
                let req = build_rootdse_search(1, attrs);
                // send and read
                if tokio::time::timeout(Duration::from_millis(500), stream.write_all(&req))
                    .await
                    .is_ok()
                {
                    let mut buf = vec![0u8; 8192];
                    if let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_millis(1000), stream.read(&mut buf))
                            .await
                    {
                        if n > 0 {
                            buf.truncate(n);
                            let decoded = decode_rootdse_response(&buf, attrs);
                            if !evidence.is_empty() {
                                evidence.push('\n');
                            }
                            evidence.push_str(&format!("altServer {} RootDSE:", url));
                            if !decoded.is_empty() {
                                evidence.push('\n');
                                evidence.push_str(&decoded);
                            }
                            followed += 1;
                        } else {
                            if !evidence.is_empty() {
                                evidence.push('\n');
                            }
                            evidence.push_str(&format!("altServer {}: no response", url));
                            followed += 1;
                        }
                    } else {
                        if !evidence.is_empty() {
                            evidence.push('\n');
                        }
                        evidence.push_str(&format!("altServer {}: read timeout", url));
                        followed += 1;
                    }
                } else {
                    if !evidence.is_empty() {
                        evidence.push('\n');
                    }
                    evidence.push_str(&format!("altServer {}: write failed", url));
                    followed += 1;
                }
            }
            _ => {
                if !evidence.is_empty() {
                    evidence.push('\n');
                }
                evidence.push_str(&format!("altServer {}: connect failed", url));
                followed += 1;
            }
        }
    }
}
