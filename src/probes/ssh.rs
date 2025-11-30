use super::Probe;
use crate::service::ServiceFingerprint;
use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use std::time::Duration;

pub struct SshProbe;

#[async_trait]
impl Probe for SshProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let addr = format!("{}:{}", ip, port);

        // First, attempt to connect with a timeout. Handle both layers of Result.
        let conn = match tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(stream)) => stream, // connected successfully
            _ => return None,         // either timeout or connect error
        };

        // Read the banner with a short read timeout
        let mut stream = conn;
        let mut buf = [0u8; 256];

        let n = match tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf)).await {
            Ok(Ok(n)) => n,   // read succeeded, n bytes
            _ => return None, // timeout or read error
        };

        if n == 0 {
            return None;
        }

        let banner = String::from_utf8_lossy(&buf[..n]).to_string();
        Some(ServiceFingerprint::from_banner(ip, port, "ssh", banner))
    }

    fn ports(&self) -> Vec<u16> {
        vec![22]
    }
    fn name(&self) -> &'static str {
        "ssh"
    }
}
