use crate::probes::{helper::push_line, Probe, ProbeContext};
use crate::service::ServiceFingerprint;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

pub struct NtpProbe;

#[async_trait::async_trait]
impl Probe for NtpProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let mut evidence = String::new();
        let mut confidence: u8 = 40;

        let timeout_dur = Duration::from_millis(timeout_ms);

        // Build standard 48-byte NTP client request
        let mut req = [0u8; 48];
        req[0] = 0b00_100_011; // LI=0, VN=4, Mode=3 (client)

        // Bind ephemeral UDP socket
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => {
                push_line(&mut evidence, "ntp", "bind_error");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "ntp", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        // Send request
        let addr = format!("{}:{}", ip, port);
        if socket.send_to(&req, &addr).await.is_err() {
            push_line(&mut evidence, "ntp", "send_error");
            let mut fp = ServiceFingerprint::from_banner(ip, port, "ntp", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }

        // Receive response
        let mut buf = [0u8; 512];
        let resp_len = match timeout(timeout_dur, socket.recv(&mut buf)).await {
            Ok(Ok(n)) if n >= 48 => n,
            _ => {
                push_line(&mut evidence, "ntp", "no_response");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "ntp", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        let resp = &buf[..resp_len];

        // Parse header fields
        let _li = (resp[0] >> 6) & 0b11;
        let vn = (resp[0] >> 3) & 0b111;
        let mode = resp[0] & 0b111;
        let stratum = resp[1];
        let ref_id = &resp[12..16];

        // Interpret reference ID
        let reference = if stratum <= 1 {
            // ASCII reference ID (e.g., "GPS", "LOCL", "PPS")
            String::from_utf8_lossy(ref_id).to_string()
        } else {
            // IPv4 address
            format!("{}.{}.{}.{}", ref_id[0], ref_id[1], ref_id[2], ref_id[3])
        };

        push_line(&mut evidence, "ntp", "response");
        push_line(&mut evidence, "ntp_version", &vn.to_string());
        push_line(&mut evidence, "ntp_mode", &mode.to_string());
        push_line(&mut evidence, "ntp_stratum", &stratum.to_string());
        push_line(&mut evidence, "ntp_reference", &reference);

        confidence = 70;

        let mut fp = ServiceFingerprint::from_banner(ip, port, "ntp", evidence);
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
        vec![123]
    }
    fn name(&self) -> &'static str {
        "ntp"
    }
}
