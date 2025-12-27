use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::probes::{Probe, ProbeContext, helper::push_line};
use crate::service::ServiceFingerprint;

pub struct RtspProbe;

#[async_trait::async_trait]
impl Probe for RtspProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let mut evidence = String::new();
        let mut confidence: u8 = 40;

        let timeout_dur = Duration::from_millis(timeout_ms);
        let addr = format!("{}:{}", ip, port);

        // Connect
        let mut stream = match timeout(timeout_dur, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => {
                push_line(&mut evidence, "rtsp", "connect_error");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "rtsp", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        // Send OPTIONS request
        let req = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n";
        if timeout(timeout_dur, stream.write_all(req)).await.is_err() {
            push_line(&mut evidence, "rtsp", "send_error");
            let mut fp = ServiceFingerprint::from_banner(ip, port, "rtsp", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }

        // Read response
        let mut buf = vec![0u8; 4096];
        let n = match timeout(timeout_dur, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => {
                push_line(&mut evidence, "rtsp", "no_response");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "rtsp", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        let resp = String::from_utf8_lossy(&buf[..n]).to_string();
        push_line(&mut evidence, "rtsp_response", resp.trim());

        // Parse useful headers
        for line in resp.lines() {
            let line = line.trim();

            if line.starts_with("Server:") {
                let val = line.trim_start_matches("Server:").trim();
                push_line(&mut evidence, "rtsp_server", val);
                confidence = 80;
            }

            if line.starts_with("Public:") {
                let val = line.trim_start_matches("Public:").trim();
                push_line(&mut evidence, "rtsp_public", val);
                confidence = 70;
            }

            if line.starts_with("WWW-Authenticate:") {
                let val = line.trim_start_matches("WWW-Authenticate:").trim();
                push_line(&mut evidence, "rtsp_auth", val);
            }
        }

        let mut fp = ServiceFingerprint::from_banner(ip, port, "rtsp", evidence);
        fp.confidence = confidence;
        Some(fp)
    }

    async fn probe_with_ctx(&self, ip: &str, port: u16, ctx: ProbeContext) -> Option<ServiceFingerprint> {
        self.probe(
            ip,
            port,
            ctx.get("timeout_ms").and_then(|s| s.parse::<u64>().ok()).unwrap_or(2000),
        ).await
    }

    fn ports(&self) -> Vec<u16> { vec![554,8554] }
    fn name(&self) -> &'static str { "rtsp" }
}
