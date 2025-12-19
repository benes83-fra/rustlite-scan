use crate::{probes::{Probe, ProbeContext, helper::{connect_with_timeout, push_line}}, service::ServiceFingerprint};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, time::*};

pub struct RedisProbe;

#[async_trait::async_trait]
impl Probe for RedisProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let mut evidence = String::new();
        let timeout_dur = Duration::from_millis(timeout_ms);

        let mut tcp = match connect_with_timeout(ip, port, timeout_ms).await {
            Some(s) => s,
            None => {
                push_line(&mut evidence, "redis", "connect_timeout");
                return Some(ServiceFingerprint::from_banner(ip, port, "redis", evidence));
            }
        };

        // Send INFO command
        if let Err(_) = timeout(timeout_dur, tcp.write_all(b"INFO\r\n")).await {
            push_line(&mut evidence, "redis", "write_error");
            return Some(ServiceFingerprint::from_banner(ip, port, "redis", evidence));
        }

        // Read response (bulk string)
        let mut buf = vec![0u8; 4096];
        match timeout(timeout_dur, tcp.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let resp = String::from_utf8_lossy(&buf[..n]);
                if resp.starts_with("$") {
                    if let Some(info) = parse_info(&resp) {
                        if let Some(ver) = info.version {
                            push_line(&mut evidence, "redis_version", &ver);
                        }
                        if let Some(mode) = info.mode {
                            push_line(&mut evidence, "redis_mode", &mode);
                        }
                        if !info.features.is_empty() {
                            push_line(&mut evidence, "redis_features", &info.features.join(", "));
                        }
                    }
                } else {
                    push_line(&mut evidence, "redis", "unexpected_response");
                }
            }
            _ => {
                push_line(&mut evidence, "redis", "read_error");
            }
        }

        Some(ServiceFingerprint::from_banner(ip, port, "redis", evidence))
    }

    async fn probe_with_ctx(&self, ip: &str, port: u16, ctx: ProbeContext) -> Option<ServiceFingerprint> {
        // Optional: support AUTH if ctx has password
        self.probe(ip, port, ctx.get("timeout_ms").and_then(|s| s.parse::<u64>().ok()).unwrap_or(2000)).await
    }

    fn ports(&self) -> Vec<u16> { vec![6379] }
    fn name(&self) -> &'static str { "redis" }
}

// --- helper types and functions ---

struct RedisInfo {
    version: Option<String>,
    mode: Option<String>,
    features: Vec<String>,
}

fn parse_info(resp: &str) -> Option<RedisInfo> {
    let mut version = None;
    let mut mode = None;
    let mut features = Vec::new();
    for line in resp.lines() {
        if line.starts_with("redis_version:") {
            version = Some(line["redis_version:".len()..].trim().to_string());
        } else if line.starts_with("redis_mode:") {
            mode = Some(line["redis_mode:".len()..].trim().to_string());
        } else if line.starts_with("module:") {
            features.push(line.to_string());
        } else if line.starts_with("rdb_changes_since_last_save:") {
            features.push("persistence".into());
        }
    }
    Some(RedisInfo { version, mode, features })
}
