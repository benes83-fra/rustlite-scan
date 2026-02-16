use crate::probes::{helper::push_line, Probe, ProbeContext};
use crate::service::ServiceFingerprint;
use md5::{Digest, Md5};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

pub struct RadiusProbe;

#[async_trait::async_trait]
impl Probe for RadiusProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let mut evidence = String::new();
        let mut confidence: u8 = 40;
        let timeout_dur = Duration::from_millis(timeout_ms);

        // --- 1) Bind ephemeral UDP socket ---
        let bind_addr = "0.0.0.0:0";
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(_) => {
                push_line(&mut evidence, "radius", "udp_bind_failed");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "radius", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        let target = format!("{}:{}", ip, port);

        // --- 2) Build minimal Access-Request (Code 1) ---

        // Attributes:
        // User-Name (1) = "rustlite-scan"
        let username = b"rustlite-scan";
        let mut attrs: Vec<u8> = Vec::new();
        attrs.push(1); // Type: User-Name
        attrs.push((2 + username.len()) as u8); // Length
        attrs.extend_from_slice(username);

        // RADIUS packet structure:
        // Code (1) | Identifier (1) | Length (2) | Authenticator (16) | Attributes...
        let length = (20 + attrs.len()) as u16;
        let secret = b"testing123";

        // Build packet with zeroed authenticator for hashing
        let mut packet_wo_auth: Vec<u8> = Vec::new();
        packet_wo_auth.push(1); // Code = Access-Request
        packet_wo_auth.push(1); // Identifier
        packet_wo_auth.extend_from_slice(&length.to_be_bytes());
        packet_wo_auth.extend_from_slice(&[0u8; 16]); // placeholder authenticator
        packet_wo_auth.extend_from_slice(&attrs);

        // Compute Request Authenticator
        let authenticator = radius_request_authenticator(secret, &packet_wo_auth);

        // Build final packet with real authenticator
        let mut packet: Vec<u8> = Vec::new();
        packet.push(1);
        packet.push(1);
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(&authenticator);
        packet.extend_from_slice(&attrs);

        // --- 3) Send packet ---
        if socket.send_to(&packet, &target).await.is_err() {
            push_line(&mut evidence, "radius", "udp_send_failed");
            let mut fp = ServiceFingerprint::from_banner(ip, port, "radius", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }

        // --- 4) Receive response ---
        let mut buf = [0u8; 2048];
        let (n, _) = match timeout(timeout_dur, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _addr))) if n > 0 => (n, _addr),
            _ => {
                push_line(&mut evidence, "radius", "no_response");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "radius", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        let resp = &buf[..n];
        push_line(&mut evidence, "radius_raw", &format!("{:02X?}", resp));

        // --- 5) Basic parsing ---
        if resp.len() < 20 {
            push_line(&mut evidence, "radius", "short_response");
            let mut fp = ServiceFingerprint::from_banner(ip, port, "radius", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }

        let code = resp[0];
        let identifier = resp[1];
        let resp_len = u16::from_be_bytes([resp[2], resp[3]]);

        push_line(
            &mut evidence,
            "radius_identifier",
            &format!("{}", identifier),
        );
        push_line(&mut evidence, "radius_length", &format!("{}", resp_len));

        let code_str = match code {
            2 => "Access-Accept",
            3 => "Access-Reject",
            11 => "Access-Challenge",
            12 => "Status-Server",
            13 => "Status-Client",
            _ => "Unknown",
        };

        push_line(
            &mut evidence,
            "radius_code",
            &format!("0x{:02X} ({})", code, code_str),
        );

        confidence = 75;

        // --- 6) Parse a couple of attributes (User-Name, NAS-IP-Address, Vendor-Specific) ---
        if resp_len as usize <= resp.len() {
            let mut offset = 20usize;
            while offset + 2 <= resp_len as usize && offset + 2 <= resp.len() {
                let atype = resp[offset];
                let alen = resp[offset + 1] as usize;
                if alen < 2 || offset + alen > resp_len as usize || offset + alen > resp.len() {
                    break;
                }
                let value = &resp[offset + 2..offset + alen];

                match atype {
                    1 => {
                        // User-Name
                        if let Ok(s) = std::str::from_utf8(value) {
                            push_line(&mut evidence, "radius_user_name", s);
                        } else {
                            push_line(
                                &mut evidence,
                                "radius_user_name_raw",
                                &format!("{:02X?}", value),
                            );
                        }
                    }
                    4 => {
                        // NAS-IP-Address
                        if value.len() == 4 {
                            let ip = format!("{}.{}.{}.{}", value[0], value[1], value[2], value[3]);
                            push_line(&mut evidence, "radius_nas_ip_address", &ip);
                        } else {
                            push_line(
                                &mut evidence,
                                "radius_nas_ip_address_raw",
                                &format!("{:02X?}", value),
                            );
                        }
                    }
                    26 => {
                        // Vendor-Specific
                        push_line(
                            &mut evidence,
                            "radius_vendor_specific",
                            &format!("{:02X?}", value),
                        );
                    }
                    _ => {
                        // ignore other attributes for now
                    }
                }

                offset += alen;
            }
        }

        let mut fp = ServiceFingerprint::from_banner(ip, port, "radius", evidence);
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
        // 1812 = auth, 1645 = legacy auth
        vec![1812, 1645]
    }

    fn name(&self) -> &'static str {
        "radius"
    }
}

fn radius_request_authenticator(secret: &[u8], packet_without_auth: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(packet_without_auth);
    hasher.update(secret);
    let result = hasher.finalize();

    let mut out = [0u8; 16];
    out.copy_from_slice(&result[..16]);
    out
}
