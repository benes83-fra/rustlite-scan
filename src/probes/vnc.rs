use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use crate::probes::{Probe, ProbeContext, helper::push_line};
use crate::service::ServiceFingerprint;

pub struct VncProbe;

#[async_trait::async_trait]
impl Probe for VncProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let mut evidence = String::new();
        let mut confidence: u8 = 40;

        let timeout_dur = Duration::from_millis(timeout_ms);
        let addr = format!("{}:{}", ip, port);

        // Connect
        let mut stream = match timeout(timeout_dur, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => {
                push_line(&mut evidence, "vnc", "connect_error");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "vnc", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        // Read server banner (should be like "RFB 003.008\n")
        let mut banner = [0u8; 12];
        let n = match timeout(timeout_dur, stream.readable()).await {
            Ok(_) => match stream.try_read(&mut banner) {
                Ok(n) if n >= 12 => n,
                _ => {
                    push_line(&mut evidence, "vnc", "no_banner");
                    let mut fp = ServiceFingerprint::from_banner(ip, port, "vnc", evidence);
                    fp.confidence = confidence;
                    return Some(fp);
                }
            },
            _ => {
                push_line(&mut evidence, "vnc", "timeout_banner");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "vnc", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        let banner_str = String::from_utf8_lossy(&banner[..n]).trim().to_string();
        push_line(&mut evidence, "vnc_banner", &banner_str);

        // Extract version
        if banner_str.starts_with("RFB ") && banner_str.len() >= 11 {
            let version = &banner_str[4..11];
            push_line(&mut evidence, "vnc_version", version);
            confidence = 60;
        }

        // Send back the same version to proceed
        if banner_str.len() >= 12 {
            let _ = stream.try_write(banner_str.as_bytes());
        }

        // Read security types
        let mut sec_buf = [0u8; 256];
        let sec_n = match timeout(timeout_dur, stream.readable()).await {
            Ok(_) => match stream.try_read(&mut sec_buf) {
                Ok(n) if n > 0 => n,
                _ => {
                    push_line(&mut evidence, "vnc", "no_security_types");
                    let mut fp = ServiceFingerprint::from_banner(ip, port, "vnc", evidence);
                    fp.confidence = confidence;
                    return Some(fp);
                }
            },
            _ => {
                push_line(&mut evidence, "vnc", "timeout_security");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "vnc", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        // Parse security types
        if sec_n >= 2 {
            let count = sec_buf[0] as usize;
            if count > 0 && sec_n >= 1 + count {
                push_line(&mut evidence, "vnc_security_count", &count.to_string());
                for i in 0..count {
                    let code = sec_buf[1 + i];
                    push_line(&mut evidence, "vnc_security_type", &format!("{}", code));
                }
                confidence = 80;
            }
        }

        let mut fp = ServiceFingerprint::from_banner(ip, port, "vnc", evidence);
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

    fn ports(&self) -> Vec<u16> { vec![5900] }
    fn name(&self) -> &'static str { "vnc" }
}
