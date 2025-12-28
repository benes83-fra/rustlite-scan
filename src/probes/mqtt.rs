use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::probes::{Probe, ProbeContext, helper::push_line};
use crate::service::ServiceFingerprint;

pub struct MqttProbe;

#[async_trait::async_trait]
impl Probe for MqttProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let mut evidence = String::new();
        let mut confidence: u8 = 40;

        let timeout_dur = Duration::from_millis(timeout_ms);

        // MQTT CONNECT packet (minimal, clean, no auth)
       let connect_packet: [u8; 22] = [
                                        0x10, 0x14,       // CONNECT, Remaining Length = 20
                                        0x00, 0x04,       // Protocol Name Length
                                        b'M', b'Q', b'T', b'T',
                                        0x04,             // Protocol Level (3.1.1)
                                        0x02,             // Flags (Clean Session)
                                        0x00, 0x3C,       // Keepalive (60)
                                        0x00, 0x08,       // Client ID length = 8
                                        b'r', b'u', b's', b't', b'l', b'i', b't', b'e'
                                    ];

        // Connect TCP
        let addr = format!("{}:{}", ip, port);
        let mut stream = match timeout(timeout_dur, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => {
                push_line(&mut evidence, "mqtt", "tcp_connect_failed");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "mqtt", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        // Send CONNECT
        if timeout(timeout_dur, stream.write_all(&connect_packet)).await.is_err() {
            push_line(&mut evidence, "mqtt", "send_error");
            let mut fp = ServiceFingerprint::from_banner(ip, port, "mqtt", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }

        // Receive CONNACK
        let mut buf = [0u8; 1024];
        let n = match timeout(timeout_dur, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => {
                push_line(&mut evidence, "mqtt", "no_response");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "mqtt", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        let resp = &buf[..n];
        push_line(&mut evidence, "mqtt_raw", &format!("{:02X?}", resp));

        // Parse CONNACK
        if resp.len() >= 4 && resp[0] == 0x20 {
            push_line(&mut evidence, "mqtt_type", "CONNACK");
            confidence = 70;

            let return_code = resp[3];
            push_line(&mut evidence, "mqtt_return_code", &format!("{}", return_code));

            match return_code {
                0x00 => push_line(&mut evidence, "mqtt_status", "Connection Accepted"),
                0x01 => push_line(&mut evidence, "mqtt_status", "Unacceptable Protocol Version"),
                0x02 => push_line(&mut evidence, "mqtt_status", "Identifier Rejected"),
                0x03 => push_line(&mut evidence, "mqtt_status", "Server Unavailable"),
                0x04 => push_line(&mut evidence, "mqtt_status", "Bad Username or Password"),
                0x05 => push_line(&mut evidence, "mqtt_status", "Not Authorized"),
                _ => push_line(&mut evidence, "mqtt_status", "Unknown Return Code"),
            }
        }

        let mut fp = ServiceFingerprint::from_banner(ip, port, "mqtt", evidence);
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

    fn ports(&self) -> Vec<u16> { vec![1883] }
    fn name(&self) -> &'static str { "mqtt" }
}
