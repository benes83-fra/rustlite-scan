use super::{Probe,BannerFields,BannerParser,format_evidence}    ;
use crate::service::ServiceFingerprint;
use async_trait::async_trait;
use tokio::io::AsyncReadExt;
use std::time::Duration;




pub struct SshBannerParser;

impl BannerParser for SshBannerParser {
    fn parse(raw: &str) -> BannerFields {
        let trimmed = raw.trim();
        let mut fields = BannerFields {
            protocol: None,
            product: None,
            version: None,
            comment: None,
        };

        if trimmed.starts_with("SSH-") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if let Some(first) = parts.get(0) {
                fields.protocol = Some(first.to_string());
                if let Some(rest) = first.strip_prefix("SSH-2.0-") {
                    let mut pv = rest.splitn(2, '_');
                    fields.product = pv.next().map(|s| s.to_string());
                    fields.version = pv.next().map(|s| s.to_string());
                }
            }
            if parts.len() > 1 {
                fields.comment = Some(parts[1..].join(" "));
            }
        }
        fields
    }
}


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
        

        let mut evidence = String::new();
        
        let fields = SshBannerParser::parse(&banner);
        let evidence = format_evidence("ssh", fields);

        Some(ServiceFingerprint {
            host: ip.to_string(),
            ip: ip.to_string(),
            port,
            protocol: "ssh".to_string(),
            service: None,
            version: None,
            evidence: Some(evidence),
            evidence_type: Some("banner".to_string()),
            confidence: 50,
            first_seen: chrono::Utc::now(),
        })

    }

    fn ports(&self) -> Vec<u16> {
        vec![22]
    }
    fn name(&self) -> &'static str {
        "ssh"
    }
}


fn parse_ssh_banner(raw: &str) -> (String, Option<String>, Option<String>, Option<String>) {
    let trimmed = raw.trim();
    // Default protocol
    let mut protocol = String::new();
    let mut product = None;
    let mut version = None;
    let mut comment = None;

    if trimmed.starts_with("SSH-") {
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if let Some(first) = parts.get(0) {
            protocol = first.to_string();
            // After "SSH-2.0-" comes product/version
            if let Some(rest) = first.strip_prefix("SSH-2.0-") {
                // e.g. "OpenSSH_9.3p1"
                let mut pv = rest.splitn(2, '_');
                product = pv.next().map(|s| s.to_string());
                version = pv.next().map(|s| s.to_string());
            }
        }
        if parts.len() > 1 {
            comment = Some(parts[1..].join(" "));
        }
    }
    (protocol, product, version, comment)
}


