use crate::probes::{helper::push_line, Probe, ProbeContext};
use crate::service::ServiceFingerprint;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

pub struct SipProbe;

#[async_trait::async_trait]
impl Probe for SipProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let mut evidence = String::new();
        let mut confidence: u8 = 40;

        let timeout_dur = Duration::from_millis(timeout_ms);

        // Build SIP OPTIONS request
        let req = format!(
            "OPTIONS sip:{} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 0.0.0.0:{};branch=z9hG4bK-1\r\n\
             Max-Forwards: 70\r\n\
             To: <sip:{}>\r\n\
             From: <sip:scanner>;tag=1234\r\n\
             Call-ID: 1@scanner\r\n\
             CSeq: 1 OPTIONS\r\n\
             Content-Length: 0\r\n\r\n",
            ip, port, ip
        );

        // Bind UDP socket
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => {
                push_line(&mut evidence, "sip", "bind_error");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "sip", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        // Send request
        let addr = format!("{}:{}", ip, port);
        if socket.send_to(req.as_bytes(), &addr).await.is_err() {
            push_line(&mut evidence, "sip", "send_error");
            let mut fp = ServiceFingerprint::from_banner(ip, port, "sip", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }

        // Receive response
        let mut buf = [0u8; 4096];
        let n = match timeout(timeout_dur, socket.recv(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => {
                push_line(&mut evidence, "sip", "no_response");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "sip", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        let resp = String::from_utf8_lossy(&buf[..n]).to_string();
        push_line(&mut evidence, "sip_response", resp.trim());

        // Parse headers
        for line in resp.lines() {
            let line = line.trim();

            if line.starts_with("Server:") {
                let val = line.trim_start_matches("Server:").trim();
                push_line(&mut evidence, "sip_server", val);
                confidence = 80;
            }

            if line.starts_with("User-Agent:") {
                let val = line.trim_start_matches("User-Agent:").trim();
                push_line(&mut evidence, "sip_user_agent", val);
                confidence = 70;
            }

            if line.starts_with("Allow:") {
                let val = line.trim_start_matches("Allow:").trim();
                push_line(&mut evidence, "sip_allow", val);
                confidence = 70;
            }

            if line.starts_with("WWW-Authenticate:") {
                let val = line.trim_start_matches("WWW-Authenticate:").trim();
                push_line(&mut evidence, "sip_auth", val);
            }
        }

        let mut fp = ServiceFingerprint::from_banner(ip, port, "sip", evidence);
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
        vec![5060]
    }
    fn name(&self) -> &'static str {
        "sip"
    }
}
