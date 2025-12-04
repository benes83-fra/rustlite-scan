use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;
use crate::service::ServiceFingerprint;
use super::Probe;

pub struct SmtpProbe;

#[async_trait]
impl Probe for SmtpProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let addr = format!("{}:{}", ip, port);
        let mut stream = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            TcpStream::connect(&addr)
        ).await;
        let mut stream = match stream {
            Ok(Ok(s)) => s,
    _       => return None, // timeout or connect error
        };;

        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.ok()?;
        let banner = String::from_utf8_lossy(&buf[..n]).to_string();

        // Send EHLO to get extensions
        let _ = stream.write_all(b"EHLO example.com\r\n").await.ok()?;
        let n = stream.read(&mut buf).await.ok()?;
        let ehlo_resp = String::from_utf8_lossy(&buf[..n]).to_string();

        let evidence = format!("{} | {}", banner.trim(), ehlo_resp.trim());
        Some(ServiceFingerprint::from_banner(ip, port, "smtp", evidence))
    }

    fn ports(&self) -> Vec<u16> { vec![25, 587, 465] }
    fn name(&self) -> &'static str { "smtp" }
}
