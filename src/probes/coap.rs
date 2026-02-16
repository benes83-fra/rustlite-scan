use crate::probes::{helper::push_line, Probe, ProbeContext};
use crate::service::ServiceFingerprint;
use rand::Rng;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

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
            push_line(
                &mut evidence,
                "coap_token",
                &format!("{:02X?}", token_bytes),
            );
            offset += tkl;
        }

        // Options: we’ll just skip them until payload marker (0xFF) or end
        let mut options: Vec<(u16, Vec<u8>)> = Vec::new();
        let mut current_opt_num: u16 = 0;

        while offset < resp.len() {
            if resp[offset] == 0xFF {
                offset += 1;
                break;
            }

            let opt_byte = resp[offset];
            offset += 1;

            let delta = (opt_byte >> 4) & 0x0F;
            let len = (opt_byte & 0x0F) as usize;

            // Extended delta/length not supported here
            if delta == 13 || delta == 14 || len == 13 || len == 14 {
                break;
            }

            current_opt_num += delta as u16;

            if offset + len > resp.len() {
                break;
            }

            let val = resp[offset..offset + len].to_vec();
            offset += len;

            options.push((current_opt_num, val));
        }
        if let Some(cf) = parse_content_format(&options) {
            push_line(&mut evidence, "coap_content_format", &format!("{}", cf));

            // Optional: human-readable mapping
            let cf_name = match cf {
                0 => "text/plain",
                40 => "application/link-format",
                41 => "application/xml",
                42 => "application/octet-stream",
                47 => "application/exi",
                50 => "application/json",
                60 => "application/cbor",
                _ => "unknown",
            };

            push_line(&mut evidence, "coap_content_format_name", cf_name);
        }

        // Payload
        if offset < resp.len() {
            let payload = &resp[offset..];

            if !payload.is_empty() {
                // Try UTF-8
                if let Ok(s) = std::str::from_utf8(payload) {
                    let snippet = if s.len() > 256 { &s[..256] } else { s };
                    push_line(&mut evidence, "coap_payload_text", snippet);
                    let resources = parse_rfc6690(s);

                    let mut enum_results = Vec::new();

                    for res in &resources {
                        let path = &res.path;

                        // Build GET request for this resource
                        let msg_id: u16 = rand::thread_rng().gen();
                        let token: [u8; 2] = rand::random();
                        let req = build_coap_get(path, msg_id, &token);

                        // Send request
                        if socket.send_to(&req, &target).await.is_err() {
                            continue;
                        }

                        // Receive response (short timeout)
                        let mut buf2 = [0u8; 2048];
                        if let Ok(Ok((n2, _))) =
                            timeout(Duration::from_millis(500), socket.recv_from(&mut buf2)).await
                        {
                            let resp2 = &buf2[..n2];

                            enum_results.push((path.clone(), resp2.to_vec()));
                        }
                    }
                    for (path, raw) in enum_results {
                        push_line(&mut evidence, "coap_enum_path", &path);

                        // Find payload marker (0xFF)
                        let payload = if let Some(idx) = raw.iter().position(|b| *b == 0xFF) {
                            &raw[idx + 1..]
                        } else {
                            &raw[..]
                        };

                        if payload.is_empty() {
                            push_line(&mut evidence, "coap_enum_payload", "<empty>");
                            continue;
                        }

                        // Try UTF-8
                        // Try UTF-8 first
                        if let Ok(s) = std::str::from_utf8(payload) {
                            push_line(&mut evidence, "coap_enum_payload_text", s.trim());
                        } else {
                            // Try CBOR
                            if let Some(decoded) = try_parse_cbor(payload) {
                                push_line(&mut evidence, "coap_enum_payload_cbor", &decoded);
                            } else {
                                push_line(
                                    &mut evidence,
                                    "coap_enum_payload_raw",
                                    &format!("{:02X?}", payload),
                                );
                            }
                        }
                    }

                    for res in &resources {
                        push_line(&mut evidence, "coap_resource", &res.path);

                        for (k, v) in &res.attrs {
                            if v.is_empty() {
                                push_line(
                                    &mut evidence,
                                    "coap_attr_flag",
                                    &format!("{} (flag)", k),
                                );
                            } else {
                                push_line(&mut evidence, "coap_attr", &format!("{}={}", k, v));
                            }
                        }
                    }
                    // Heuristic vendor hints from payload

                    let vendor = detect_coap_vendor(&resources, s);
                    if let Some(v) = vendor {
                        push_line(&mut evidence, "coap_vendor", v);
                        confidence = confidence.max(85);
                    }
                    let capabilities = detect_coap_capabilities(&resources);

                    for cap in &capabilities {
                        push_line(&mut evidence, "coap_capability", cap);
                        confidence = confidence.max(80);
                    }
                    push_line(
                        &mut evidence,
                        "coap_summary",
                        &format!(
                            "Device exposes {} resource(s); capabilities: {}; vendor: {}",
                            resources.len(),
                            capabilities.join(", "),
                            vendor.unwrap_or("unknown")
                        ),
                    );
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
    let first = ((COAP_VERSION & 0x03) << 6)
        | ((CoapType::Confirmable as u8 & 0x03) << 4)
        | (tkl as u8 & 0x0F);

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

fn detect_coap_vendor(resources: &[CoapResource], payload: &str) -> Option<&'static str> {
    let payload_lower = payload.to_lowercase();

    for sig in COAP_VENDOR_SIGNATURES {
        // Path match
        let path_hit = sig.path_contains.iter().any(|needle| {
            resources
                .iter()
                .any(|r| r.path.to_lowercase().contains(needle))
        });

        // rt= match
        let rt_hit = sig.rt_contains.iter().any(|needle| {
            resources.iter().any(|r| {
                r.attrs
                    .iter()
                    .any(|(k, v)| k == "rt" && v.to_lowercase().contains(needle))
            })
        });

        // if= match
        let if_hit = sig.if_contains.iter().any(|needle| {
            resources.iter().any(|r| {
                r.attrs
                    .iter()
                    .any(|(k, v)| k == "if" && v.to_lowercase().contains(needle))
            })
        });

        // Payload match
        let payload_hit = sig
            .payload_contains
            .iter()
            .any(|needle| payload_lower.contains(needle));

        if path_hit || rt_hit || if_hit || payload_hit {
            return Some(sig.vendor);
        }
    }

    None
}

#[derive(Debug)]
pub struct CoapVendorSignature {
    pub vendor: &'static str,
    pub path_contains: &'static [&'static str],
    pub rt_contains: &'static [&'static str],
    pub if_contains: &'static [&'static str],
    pub payload_contains: &'static [&'static str],
}

pub const COAP_VENDOR_SIGNATURES: &[CoapVendorSignature] = &[
    // --- Philips Hue ---
    CoapVendorSignature {
        vendor: "philips_hue",
        path_contains: &["lights", "sensors", "groups"],
        rt_contains: &["core.light", "core.sensor", "hue"],
        if_contains: &["sensor", "light"],
        payload_contains: &["philips", "hue"],
    },
    // --- IKEA Tradfri ---
    CoapVendorSignature {
        vendor: "ikea_tradfri",
        path_contains: &["15001", "15004", "tradfri"],
        rt_contains: &["core.light", "core.group"],
        if_contains: &[],
        payload_contains: &["tradfri", "ikea"],
    },
    // --- Shelly ---
    CoapVendorSignature {
        vendor: "shelly",
        path_contains: &["shelly", "rpc"],
        rt_contains: &["shelly"],
        if_contains: &[],
        payload_contains: &["shelly"],
    },
    // --- Sonoff ---
    CoapVendorSignature {
        vendor: "sonoff",
        path_contains: &["zeroconf", "sonoff"],
        rt_contains: &[],
        if_contains: &[],
        payload_contains: &["sonoff"],
    },
    // --- Tuya ---
    CoapVendorSignature {
        vendor: "tuya",
        path_contains: &["tuya"],
        rt_contains: &[],
        if_contains: &[],
        payload_contains: &["tuya"],
    },
    // --- Bosch ---
    CoapVendorSignature {
        vendor: "bosch",
        path_contains: &["bosch", "device"],
        rt_contains: &["bosch"],
        if_contains: &[],
        payload_contains: &["bosch"],
    },
    // --- LwM2M (OMA Lightweight M2M) ---
    CoapVendorSignature {
        vendor: "lwm2m",
        path_contains: &["rd", "d/"], // LwM2M uses /rd, /d/<id>, /s/<id>

        rt_contains: &["oma.lwm2m"],
        if_contains: &["lwm2m"],
        payload_contains: &["lwm2m", "oma"],
    },
    // --- Generic IoT sensors ---
    CoapVendorSignature {
        vendor: "generic_sensor",
        path_contains: &["sensor", "sensors", "obs"],
        rt_contains: &["sensor", "observe", "temperature", "humidity"],
        if_contains: &["sensor"],
        payload_contains: &["sensor", "observe"],
    },
];

#[derive(Debug)]
pub struct CoapCapabilitySignature {
    pub capability: &'static str,
    pub path_contains: &'static [&'static str],
    pub rt_contains: &'static [&'static str],
    pub if_contains: &'static [&'static str],
    pub flags: &'static [&'static str],
}

pub const COAP_CAPABILITY_SIGNATURES: &[CoapCapabilitySignature] = &[
    // --- Observable resource ---
    CoapCapabilitySignature {
        capability: "observable",
        path_contains: &["obs"],
        rt_contains: &["observe"],
        if_contains: &[],
        flags: &["obs"],
    },
    // --- Temperature sensor ---
    CoapCapabilitySignature {
        capability: "temperature_sensor",
        path_contains: &["temp", "temperature"],
        rt_contains: &["temperature", "temperature-c"],
        if_contains: &["sensor"],
        flags: &[],
    },
    // --- Humidity sensor ---
    CoapCapabilitySignature {
        capability: "humidity_sensor",
        path_contains: &["humidity"],
        rt_contains: &["humidity"],
        if_contains: &["sensor"],
        flags: &[],
    },
    // --- Light / lamp ---
    CoapCapabilitySignature {
        capability: "light",
        path_contains: &["light", "lights"],
        rt_contains: &["core.light", "light"],
        if_contains: &["light"],
        flags: &[],
    },
    // --- Switch / relay ---
    CoapCapabilitySignature {
        capability: "switch",
        path_contains: &["switch", "relay"],
        rt_contains: &["switch"],
        if_contains: &["control"],
        flags: &[],
    },
    // --- Thermostat ---
    CoapCapabilitySignature {
        capability: "thermostat",
        path_contains: &["thermostat"],
        rt_contains: &["thermostat"],
        if_contains: &[],
        flags: &[],
    },
    // --- Generic sensor ---
    CoapCapabilitySignature {
        capability: "sensor",
        path_contains: &["sensor", "sensors"],
        rt_contains: &["sensor"],
        if_contains: &["sensor"],
        flags: &[],
    },
    // --- Generic actuator ---
    CoapCapabilitySignature {
        capability: "actuator",
        path_contains: &["actuator"],
        rt_contains: &["actuator"],
        if_contains: &["control"],
        flags: &[],
    },
];
fn detect_coap_capabilities(resources: &[CoapResource]) -> Vec<&'static str> {
    let mut caps = Vec::new();

    for sig in COAP_CAPABILITY_SIGNATURES {
        let mut hit = false;

        // Path match
        if sig.path_contains.iter().any(|needle| {
            resources
                .iter()
                .any(|r| r.path.to_lowercase().contains(needle))
        }) {
            hit = true;
        }

        // rt= match
        if sig.rt_contains.iter().any(|needle| {
            resources.iter().any(|r| {
                r.attrs
                    .iter()
                    .any(|(k, v)| k == "rt" && v.to_lowercase().contains(needle))
            })
        }) {
            hit = true;
        }

        // if= match
        if sig.if_contains.iter().any(|needle| {
            resources.iter().any(|r| {
                r.attrs
                    .iter()
                    .any(|(k, v)| k == "if" && v.to_lowercase().contains(needle))
            })
        }) {
            hit = true;
        }

        // Flag match
        if sig.flags.iter().any(|needle| {
            resources
                .iter()
                .any(|r| r.attrs.iter().any(|(k, _)| k == needle))
        }) {
            hit = true;
        }

        if hit {
            caps.push(sig.capability);
        }
    }

    caps
}

fn build_coap_get(path: &str, msg_id: u16, token: &[u8]) -> Vec<u8> {
    let tkl = token.len();
    let first = ((COAP_VERSION & 0x03) << 6)
        | ((CoapType::Confirmable as u8 & 0x03) << 4)
        | (tkl as u8 & 0x0F);

    let code = CoapCode::Get as u8;
    let msg_id_bytes = msg_id.to_be_bytes();

    let mut packet = Vec::new();
    packet.push(first);
    packet.push(code);
    packet.extend_from_slice(&msg_id_bytes);
    packet.extend_from_slice(token);

    // Encode Uri-Path options
    let mut last_opt = 0u8;
    for segment in path.trim_start_matches('/').split('/') {
        if segment.is_empty() {
            continue;
        }

        let opt_num = 11u8; // Uri-Path
        let delta = opt_num - last_opt;
        last_opt = opt_num;

        let len = segment.len() as u8;
        let opt_byte = ((delta & 0x0F) << 4) | (len & 0x0F);

        packet.push(opt_byte);
        packet.extend_from_slice(segment.as_bytes());
    }

    packet
}

fn parse_content_format(options: &[(u16, Vec<u8>)]) -> Option<u16> {
    for (opt_num, opt_val) in options {
        if *opt_num == 12 {
            // Content-Format is an unsigned integer encoded in 0–2 bytes
            if opt_val.is_empty() {
                return Some(0);
            }
            if opt_val.len() == 1 {
                return Some(opt_val[0] as u16);
            }
            if opt_val.len() == 2 {
                return Some(u16::from_be_bytes([opt_val[0], opt_val[1]]));
            }
        }
    }
    None
}

fn try_parse_cbor(payload: &[u8]) -> Option<String> {
    match serde_cbor::from_slice::<serde_cbor::Value>(payload) {
        Ok(val) => Some(format!("{:?}", val)),
        Err(_) => None,
    }
}
