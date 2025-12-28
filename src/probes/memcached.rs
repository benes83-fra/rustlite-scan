use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::probes::{Probe, ProbeContext, helper::push_line};
use crate::service::ServiceFingerprint;

pub struct MemcachedProbe;

#[async_trait::async_trait]
impl Probe for MemcachedProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let mut evidence = String::new();
        let mut confidence: u8 = 40;

        let timeout_dur = Duration::from_millis(timeout_ms);

        // Connect TCP
        let addr = format!("{}:{}", ip, port);
        let mut stream = match timeout(timeout_dur, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => {
                push_line(&mut evidence, "memcached", "tcp_connect_failed");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "memcached", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        // Send "version\r\n"
        if timeout(timeout_dur, stream.write_all(b"version\r\n")).await.is_err() {
            push_line(&mut evidence, "memcached", "send_error");
            let mut fp = ServiceFingerprint::from_banner(ip, port, "memcached", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }

        // Receive response
        let mut buf = [0u8; 1024];
        let n = match timeout(timeout_dur, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => {
                push_line(&mut evidence, "memcached", "no_response");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "memcached", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        let resp = String::from_utf8_lossy(&buf[..n]).to_string();
        push_line(&mut evidence, "memcached_response", resp.trim());

        // Parse version
        if resp.starts_with("VERSION") {
            let parts: Vec<&str> = resp.split_whitespace().collect();
            if parts.len() >= 2 {
                push_line(&mut evidence, "memcached_version", parts[1]);
                confidence = 80;
            }
        }

        let mut fp = ServiceFingerprint::from_banner(ip, port, "memcached", evidence);
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

    fn ports(&self) -> Vec<u16> { vec![11211] }
    fn name(&self) -> &'static str { "memcached" }
}
