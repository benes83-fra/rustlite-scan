use super::Probe;
use crate::service::ServiceFingerprint;
use async_trait::async_trait;
use std::time::Duration;
use reqwest::Client;

pub struct HttpProbe;

#[async_trait]
impl Probe for HttpProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        // Build URL (prefer https for common TLS port)
        let url = if port == 443 {
            format!("https://{}:{}/", ip, port)
        } else {
            format!("http://{}:{}/", ip, port)
        };

        // Build client with timeout; accept invalid certs to allow cert inspection on test/self-signed hosts
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .ok()?;

        // Perform a simple GET (no body read beyond headers by default)
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return None,
        };

        // Extract Server header and status code
        let server_header = resp
            .headers()
            .get("server")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let status = Some(resp.status().as_u16());

        // Build fingerprint using the new constructor
        let fp = ServiceFingerprint::from_http(ip, port, server_header, status);

        Some(fp)
    }

    fn ports(&self) -> Vec<u16> {
        vec![80, 8080, 8000, 443, 8443]
    }

    fn name(&self) -> &'static str {
        "http"
    }
}
