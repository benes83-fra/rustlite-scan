use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;

use crate::service::ServiceFingerprint;
use super::Probe;

pub struct FtpProbe;

#[async_trait]
impl Probe for FtpProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let addr = format!("{}:{}", ip, port);
        let mut stream = match tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            TcpStream::connect(&addr)
        ).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };

        let mut evidence = String::new();

        // Banner
        let banner = read_chunk(&mut stream).await?;
        push_line(&mut evidence, "Banner", banner.trim());

        // Login as anonymous
        stream.write_all(b"USER anonymous\r\n").await.ok()?;
        sleep(Duration::from_millis(1000)).await;
        let user_reply = read_multiline(&mut stream).await.unwrap_or_default();
        push_line(&mut evidence, "USER reply", user_reply.trim());

        stream.write_all(b"PASS anonymous@\r\n").await.ok()?;
        let pass_reply = read_multiline(&mut stream).await.unwrap_or_default();
        push_line(&mut evidence, "PASS reply", pass_reply.trim());

        // Request features
        stream.write_all(b"FEAT\r\n").await.ok()?;
        let feat_resp = read_feat_response(&mut stream).await.unwrap_or_default();
        push_line(&mut evidence, "Features", feat_resp.trim());

        Some(ServiceFingerprint::from_banner(ip, port, "ftp", evidence))
    }

    fn ports(&self) -> Vec<u16> { vec![21] }
    fn name(&self) -> &'static str { "ftp" }
}

// --- Helpers ---

async fn read_chunk(stream: &mut TcpStream) -> Option<String> {
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.ok()?;
    if n == 0 { return None; }
    Some(String::from_utf8_lossy(&buf[..n]).to_string())
}

async fn read_multiline(stream: &mut TcpStream) -> Option<String> {
    let mut out = String::new();
    let mut buf = [0u8; 1024];

    let n = stream.read(&mut buf).await.ok()?;
    if n == 0 { return None; }
    out.push_str(&String::from_utf8_lossy(&buf[..n]));

    // Keep reading until timeout or no more data
    loop {
        let more = tokio::time::timeout(Duration::from_millis(200), stream.read(&mut buf)).await.ok();
        match more {
            Some(Ok(m)) if m > 0 => out.push_str(&String::from_utf8_lossy(&buf[..m])),
            _ => break,
        }
    }
    Some(out)
}

// Specialized reader for FEAT response (ends with "211 End")
async fn read_feat_response(stream: &mut TcpStream) -> Option<String> {
    let mut out = String::new();
    let mut buf = [0u8; 1024];

    let n = stream.read(&mut buf).await.ok()?;
    if n == 0 { return None; }
    out.push_str(&String::from_utf8_lossy(&buf[..n]));

    loop {
        if out.contains("211 End") { break; }
        let more = tokio::time::timeout(Duration::from_millis(200), stream.read(&mut buf)).await.ok();
        match more {
            Some(Ok(m)) if m > 0 => out.push_str(&String::from_utf8_lossy(&buf[..m])),
            _ => break,
        }
    }
    Some(out)
}

fn push_line(out: &mut String, label: &str, value: &str) {
    if !out.is_empty() { out.push('\n'); }
    out.push_str(label);
    out.push_str(": ");
    out.push_str(value);
}
