use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;
use std::io::Error;
use crate::service::ServiceFingerprint;
use super::Probe;

pub struct FtpProbe;

#[async_trait]
impl Probe for FtpProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let addr = format!("{}:{}", ip, port);
        let mut stream = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            TcpStream::connect(&addr)
        ).await;
        let mut stream = match stream {
            Ok(Ok(s)) => s,
            _=> return None, // timeout or connect error
        };
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.ok()?;
        let banner = String::from_utf8_lossy(&buf[..n]).to_string();

        // Ask for features
        let _ = stream.write_all(b"FEAT\r\n").await.ok()?;
        let n = stream.read(&mut buf).await.ok()?;
        let feat_resp = String::from_utf8_lossy(&buf[..n]).to_string();

        let evidence = format!("{} | {}", banner.trim(), feat_resp.trim());
        Some(ServiceFingerprint::from_banner(ip, port, "ftp", evidence))
    }

    fn ports(&self) -> Vec<u16> { vec![21] }
    fn name(&self) -> &'static str { "ftp" }
}
