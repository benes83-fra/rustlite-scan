use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use crate::probes::{Probe, ProbeContext, helper::push_line};
use crate::service::ServiceFingerprint;
use rand::Rng;

/// CoAP version is always 1
const COAP_VERSION: u8 = 0x01;

/// CoAP message type
#[allow(dead_code)]
enum CoapType {
    Confirmable = 0x00,
    NonConfirmable = 0x01,
    Acknowledgement = 0x02,
    Reset = 0x03,
}

/// CoAP method / response codes
#[allow(dead_code)]
enum CoapCode {
    Empty = 0x00,
    Get = 0x01, // 0.01
    Post = 0x02,
    Put = 0x03,
    Delete = 0x04,
}

pub struct CoapProbe;

#[async_trait::async_trait]
impl Probe for CoapProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let mut evidence = String::new();
        let mut confidence: u8 = 40;
        let timeout_dur = Duration::from_millis(timeout_ms);

        // --- 1) Bind ephemeral UDP socket ---
        let bind_addr = "0.0.0.0:0";
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(_) => {
                push_line(&mut evidence, "coap", "udp_bind_failed");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "coap", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        let target = format!("{}:{}", ip, port);

        // --- 2) Build CoAP GET /.well-known/core ---
        let msg_id: u16 = rand::thread_rng().gen();
        let token: [u8; 2] = rand::random(); // small token length = 2

        let packet = build_coap_get_well_known_core(msg_id, &token);

        // --- 3) Send packet ---
        if socket.send_to(&packet, &target).await.is_err() {
            push_line(&mut evidence, "coap", "udp_send_failed");
            let mut fp = ServiceFingerprint::from_banner(ip, port, "coap", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }

        // --- 4) Receive response ---
        let mut buf = [0u8; 2048];
        let (n, _) = match timeout(timeout_dur, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _addr))) if n > 0 => (n, _addr),
            _ => {
                push_line(&mut evidence, "coap", "no_response");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "coap", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        let resp = &buf[..n];
        push_line(&mut evidence, "coap_raw", &format!("{:02X?}", resp));

        // --- 5) Basic CoAP header parsing ---
        if resp.len() < 4 {
            push_line(&mut evidence, "coap", "short_response");
            let mut fp = ServiceFingerprint::from_banner(ip, port, "coap", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }

        let first = resp[0];
        let version = (first & 0b1100_0000) >> 6;
        let msg_type = (first & 0b0011_0000) >> 4;
        let tkl = (first & 0b0000_1111) as usize;
        let code = resp[1];
        let resp_msg_id = u16::from_be_bytes([resp[2], resp[3]]);

        push_line(&mut evidence, "coap_version", &format!("{}", version));
        push_line(&mut evidence, "coap_type", &format!("{}", msg_type));
        push_line(&mut evidence, "coap_code_raw", &format!("0x{:02X}", code));
        push_line(&mut evidence, "coap_msg_id", &format!("{}", resp_msg_id));

        if version != COAP_VERSION {
            push_line(&mut evidence, "coap", "unexpected_version");
        }

        // CoAP response codes: class.detail (e.g. 2.05 Content)
        let code_class = code >> 5;
        let code_detail = code & 0b0001_1111;
        push_line(
            &mut evidence,
            "coap_code",
            &format!("{}.{}", code_class, code_detail),
        );

        // Basic confidence bump: valid-looking CoAP response
        if code != 0x00 {
            confidence = confidence.max(70);
        }

        // --- 6) Parse token and payload (if any) ---
        let mut offset = 4usize;

        // Token
        if tkl > 0 {
            if resp.len() < 4 + tkl {
                push_line(&mut evidence, "coap", "token_length_mismatch");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "coap", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
            let token_bytes = &resp[offset..offset + tkl];
            push_line(&mut evidence, "coap_token", &format!("{:02X?}", token_bytes));
            offset += tkl;
        }

        // Options: we’ll just skip them until payload marker (0xFF) or end
        while offset < resp.len() {
            if resp[offset] == 0xFF {
                offset += 1;
                break;
            }

            // Option byte: 4 bits delta, 4 bits length
            let opt_byte = resp[offset];
            let opt_delta = (opt_byte & 0b1111_0000) >> 4;
            let opt_len = (opt_byte & 0b0000_1111) as usize;
            offset += 1;

            // Extended delta/length not handled in detail here — if present, bail out gracefully
            if opt_delta == 13 || opt_delta == 14 || opt_len == 13 || opt_len == 14 {
                // For fingerprinting, we don't need full option decoding
                break;
            }

            if offset + opt_len > resp.len() {
                break;
            }

            let _opt_val = &resp[offset..offset + opt_len];
            offset += opt_len;
        }

        // Payload
        if offset < resp.len() {
            let payload = &resp[offset..];

            if !payload.is_empty() {
                // Try UTF-8
                if let Ok(s) = std::str::from_utf8(payload) {
                    let snippet = if s.len() > 256 {
                        &s[..256]
                    } else {
                        s
                    };
                    push_line(&mut evidence, "coap_payload_text", snippet);
                    let resources = parse_rfc6690(s);
                    for res in resources { 
                        push_line(&mut evidence, "coap_resource", &res.path); 
                        
                        for (k, v) in res.attrs { 
                            if v.is_empty() { 
                                push_line(&mut  evidence, "coap_attr_flag", &format!("{} (flag)", k));
                             } else {
                                 push_line(&mut evidence, "coap_attr", &format!("{}={}", k, v));
                                } 
                        } 
                    }
                    // Heuristic vendor hints from payload
                    let upper = snippet.to_uppercase();
                    let mut vendor = None;
                    if upper.contains("HUE") || upper.contains("PHILIPS") {
                        vendor = Some("philips_hue");
                    } else if upper.contains("SHELLY") {
                        vendor = Some("shelly");
                    } else if upper.contains("SONOFF") {
                        vendor = Some("sonoff");
                    } else if upper.contains("TUYA") {
                        vendor = Some("tuya");
                    } else if upper.contains("BOSCH") {
                        vendor = Some("bosch");
                    }

                    if let Some(v) = vendor {
                        push_line(&mut evidence, "coap_vendor", v);
                        confidence = confidence.max(80);
                    }
                } else {
                    push_line(
                        &mut evidence,
                        "coap_payload_raw",
                        &format!("{:02X?}", payload),
                    );
                }
            }
        }

        let mut fp = ServiceFingerprint::from_banner(ip, port, "coap", evidence);
        fp.confidence = confidence;
        Some(fp)
    }

    async fn probe_with_ctx(
        &self,
        ip: &str,
        port: u16,
        ctx: ProbeContext,
    ) -> Option<ServiceFingerprint> {
        self.probe(
            ip,
            port,
            ctx.get("timeout_ms")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(2000),
        )
        .await
    }

    fn ports(&self) -> Vec<u16> {
        // 5683 = default CoAP, 5684 = CoAPS (DTLS, but we just try plain UDP)
        vec![5683]
    }

    fn name(&self) -> &'static str {
        "coap"
    }
}

// --- Internal helper to build a CoAP GET /.well-known/core ---

fn build_coap_get_well_known_core(msg_id: u16, token: &[u8]) -> Vec<u8> {
    // Header:
    // Ver (2 bits) = 1
    // Type (2 bits) = Confirmable (0)
    // TKL (4 bits) = token length
    let tkl = token.len();
    let first =
        ((COAP_VERSION & 0x03) << 6) |
        ((CoapType::Confirmable as u8 & 0x03) << 4) |
        (tkl as u8 & 0x0F);

    let code = CoapCode::Get as u8; // 0.01
    let msg_id_bytes = msg_id.to_be_bytes();

    let mut packet = Vec::new();
    packet.push(first);
    packet.push(code);
    packet.extend_from_slice(&msg_id_bytes);

    // Token
    packet.extend_from_slice(token);

    // Options:
    // Uri-Path: ".well-known"
    // Uri-Path: "core"
    //
    // CoAP option encoding: (delta << 4) | length
    // For simplicity we use small option numbers and no extended fields.
    // Uri-Path is option number 11.

    // First Uri-Path: ".well-known"
    let uri_path_number = 11u8;
    let mut last_option_number = 0u8;

    let opt_delta1 = uri_path_number - last_option_number; // 11 - 0 = 11
    let val1 = b".well-known";
    let opt_len1 = val1.len() as u8;
    let opt_byte1 = ((opt_delta1 & 0x0F) << 4) | (opt_len1 & 0x0F);
    packet.push(opt_byte1);
    packet.extend_from_slice(val1);
    last_option_number = uri_path_number;

    // Second Uri-Path: "core"
    let uri_path_number2 = 11u8; // same option number, delta = 0
    let opt_delta2 = uri_path_number2 - last_option_number; // 0
    let val2 = b"core";
    let opt_len2 = val2.len() as u8;
    let opt_byte2 = ((opt_delta2 & 0x0F) << 4) | (opt_len2 & 0x0F);
    packet.push(opt_byte2);
    packet.extend_from_slice(val2);

    // No payload marker / payload for the request
    packet
}
#[derive(Debug)]
struct CoapResource {
    path: String,
    attrs: Vec<(String, String)>, // key="value" or key="" for flags
}

fn parse_rfc6690(payload: &str) -> Vec<CoapResource> {
    let mut resources = Vec::new();

    // Split by comma: each entry is a resource description
    for entry in payload.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        // Must start with </path>
        if !entry.starts_with('<') {
            continue;
        }

        let end = match entry.find('>') {
            Some(i) => i,
            None => continue,
        };

        let path = entry[1..end].to_string(); // strip < >

        let mut attrs = Vec::new();
        let mut rest = &entry[end + 1..];

        // Parse attributes: ;key=value or ;flag
        while let Some(idx) = rest.find(';') {
            rest = &rest[idx + 1..];

            // Find next semicolon or end
            let next = rest.find(';').unwrap_or(rest.len());
            let attr = rest[..next].trim();

            if attr.is_empty() {
                continue;
            }

            // key=value or key="value"
            if let Some(eq) = attr.find('=') {
                let key = attr[..eq].trim().to_string();
                let mut val = attr[eq + 1..].trim().to_string();

                // Strip quotes if present
                if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
                    val = val[1..val.len() - 1].to_string();
                }

                attrs.push((key, val));
            } else {
                // Flag attribute: e.g. "obs"
                attrs.push((attr.to_string(), "".to_string()));
            }

            rest = &rest[next..];
        }

        resources.push(CoapResource { path, attrs });
    }

    resources
}
