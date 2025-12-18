use crate::probes::helper::{push_line, connect_with_timeout};
use crate::probes::ProbeContext;
use crate::service::ServiceFingerprint;
use super::Probe;
use tokio::time::{timeout, Duration};
use tokio::io::AsyncReadExt;

pub struct MysqlProbe;

#[async_trait::async_trait]
impl Probe for MysqlProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let mut evidence = String::new();
        let timeout_dur = Duration::from_millis(timeout_ms);

        // 1) Connect
        let mut tcp = match connect_with_timeout(ip, port, timeout_ms).await {
            Some(s) => s,
            None => {
                push_line(&mut evidence, "mysql", "connect_timeout");
                return Some(ServiceFingerprint::from_banner(ip, port, "mysql", evidence));
            }
        };

        // 2) Read handshake packet
        let mut buf = vec![0u8; 256]; // handshake is usually < 256 bytes
        match timeout(timeout_dur, tcp.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let handshake = &buf[..n];
                if let Some(info) = parse_handshake(handshake) {
                    if let Some(ver) = info.server_version {
                        push_line(&mut evidence, "mysql_version", &ver);
                    }
                    push_line(&mut evidence, "mysql_protocol_version", &info.protocol_version.to_string());
                    if let Some(plugin) = info.auth_plugin {
                        push_line(&mut evidence, "mysql_auth_plugin", &plugin);
                    }
                    push_line(&mut evidence, "mysql_capabilities", &format!("0x{:08x}", info.capabilities));
                } else {
                    push_line(&mut evidence, "mysql", "handshake_parse_failed");
                }
            }
            _ => {
                push_line(&mut evidence, "mysql", "handshake_read_failed");
            }
        }

        Some(ServiceFingerprint::from_banner(ip, port, "mysql", evidence))
    }

    async fn probe_with_ctx(&self, ip: &str, port: u16, ctx: ProbeContext) -> Option<ServiceFingerprint> {
        // optional credentialed path (login attempt) — can be added later
        self.probe(ip, port, ctx.get("timeout_ms").and_then(|s| s.parse::<u64>().ok()).unwrap_or(2000)).await
    }

    fn ports(&self) -> Vec<u16> { vec![3306] }
    fn name(&self) -> &'static str { "mysql" }
}

// --- helper types and functions ---

pub struct MysqlInfo {
   pub protocol_version: u8,
   pub server_version: Option<String>,
   pub capabilities: u32,
   pub auth_plugin: Option<String>,
}

pub fn parse_handshake(buf: &[u8]) -> Option<MysqlInfo> {
    let mut i = 0;
    if buf.len() < 10 { return None; }

    let proto = buf[i]; i += 1;

    // server version string (NUL terminated)
    let mut ver_end = i;
    while ver_end < buf.len() && buf[ver_end] != 0 { ver_end += 1; }
    let server_version = String::from_utf8_lossy(&buf[i..ver_end]).to_string();
    i = ver_end + 1;

    // skip connection id (4 bytes)
    if i + 4 > buf.len() { return None; }
    i += 4;

    // skip auth plugin data part 1 (8 bytes + filler)
    if i + 9 > buf.len() { return None; }
    i += 9;

    // capability flags lower 2 bytes
    if i + 2 > buf.len() { return None; }
    let cap_low = u16::from_le_bytes([buf[i], buf[i+1]]);
    i += 2;

    // skip charset + status + upper 2 bytes of capabilities
    if i + 5 > buf.len() { return None; }
    let cap_high = u16::from_le_bytes([buf[i+3], buf[i+4]]);
    let capabilities = ((cap_high as u32) << 16) | (cap_low as u32);
    i += 5;

    // skip auth plugin length + reserved
    if i + 11 > buf.len() { return None; }
    let plugin_len = buf[i];
    i += 11;

    // auth plugin name (NUL terminated)
    let mut plugin_end = i;
    while plugin_end < buf.len() && buf[plugin_end] != 0 { plugin_end += 1; }
    let auth_plugin = if plugin_end > i {
        Some(String::from_utf8_lossy(&buf[i..plugin_end]).to_string())
    } else { None };

    Some(MysqlInfo {
        protocol_version: proto,
        server_version: Some(server_version),
        capabilities,
        auth_plugin,
    })
}
