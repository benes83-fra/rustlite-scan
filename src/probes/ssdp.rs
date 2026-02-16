use crate::probes::{helper::push_line, Probe, ProbeContext};
use crate::service::ServiceFingerprint;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

pub struct SsdpProbe;

#[async_trait::async_trait]
impl Probe for SsdpProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let mut evidence = String::new();
        let mut confidence: u8 = 40;

        let timeout_dur = Duration::from_millis(timeout_ms);

        // SSDP M-SEARCH request
        let req = format!(
            "M-SEARCH * HTTP/1.1\r\n\
             HOST: {}:{}\r\n\
             MAN: \"ssdp:discover\"\r\n\
             MX: 1\r\n\
             ST: ssdp:all\r\n\r\n",
            ip, port
        );

        // Bind UDP socket
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => {
                push_line(&mut evidence, "ssdp", "bind_error");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "ssdp", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        // Send M-SEARCH
        let addr = format!("{}:{}", ip, port);
        if socket.send_to(req.as_bytes(), &addr).await.is_err() {
            push_line(&mut evidence, "ssdp", "send_error");
            let mut fp = ServiceFingerprint::from_banner(ip, port, "ssdp", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }

        // Receive response
        let mut buf = [0u8; 4096];
        let n = match timeout(timeout_dur, socket.recv(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => {
                push_line(&mut evidence, "ssdp", "no_response");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "ssdp", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        let resp = String::from_utf8_lossy(&buf[..n]).to_string();
        push_line(&mut evidence, "ssdp_response", resp.trim());

        // Parse headers
        for line in resp.lines() {
            let line = line.trim();

            if line.to_uppercase().starts_with("SERVER:") {
                let val = line[7..].trim();
                push_line(&mut evidence, "ssdp_server", val);
                confidence = 80;
            }

            if line.to_uppercase().starts_with("ST:") {
                let val = line[3..].trim();
                push_line(&mut evidence, "ssdp_st", val);
                confidence = 70;
            }

            if line.to_uppercase().starts_with("USN:") {
                let val = line[4..].trim();
                push_line(&mut evidence, "ssdp_usn", val);
            }

            if line.to_uppercase().starts_with("LOCATION:") {
                let val = line[9..].trim();
                push_line(&mut evidence, "ssdp_location", val);
            }
        }

        let mut fp = ServiceFingerprint::from_banner(ip, port, "ssdp", evidence);
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
        vec![1900]
    }
    fn name(&self) -> &'static str {
        "ssdp"
    }
}
