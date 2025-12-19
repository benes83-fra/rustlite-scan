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
                    let caps_str = format!("0x{:08x}", info.capabilities);
                    push_line(&mut evidence, "mysql_capabilities", &caps_str);

                    let features = decode_capabilities(info.capabilities);
                    if !features.is_empty() {
                        push_line(&mut evidence, "mysql_features", &features.join(", "));
                    }

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

    fn ports(&self) -> Vec<u16> { vec![3306, 3307] }
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
    if buf.len() < 5 { return None; }
    // skip 4-byte packet header
    let mut i = 4;

    let proto = buf[i]; i += 1;

    // server version string
    let mut ver_end = i;
    while ver_end < buf.len() && buf[ver_end] != 0 { ver_end += 1; }
    let server_version = String::from_utf8_lossy(&buf[i..ver_end]).to_string();
    i = ver_end + 1;

    // connection id
    if i + 4 > buf.len() { return None; }
    i += 4;

    // auth plugin data part 1
    if i + 8 > buf.len() { return None; }
    i += 8;

    // filler
    i += 1;

    // capability flags lower
    if i + 2 > buf.len() { return None; }
    let cap_low = u16::from_le_bytes([buf[i], buf[i+1]]);
    i += 2;

    // charset + status
    i += 3;

    // capability flags upper
    if i + 2 > buf.len() { return None; }
    let cap_high = u16::from_le_bytes([buf[i], buf[i+1]]);
    i += 2;

    let capabilities = ((cap_high as u32) << 16) | (cap_low as u32);

    // auth plugin length
    let plugin_len = buf[i]; i += 1;

    // reserved
    i += 10;

    // skip rest of auth plugin data part 2
    i += plugin_len as usize;

    // auth plugin name
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
fn decode_capabilities(bits: u32) -> Vec<&'static str> {
    let mut features = Vec::new();
    if bits & 0x00000001 != 0 { features.push("CLIENT_LONG_PASSWORD"); }
    if bits & 0x00000002 != 0 { features.push("CLIENT_FOUND_ROWS"); }
    if bits & 0x00000004 != 0 { features.push("CLIENT_LONG_FLAG"); }
    if bits & 0x00000008 != 0 { features.push("CLIENT_CONNECT_WITH_DB"); }
    if bits & 0x00000010 != 0 { features.push("CLIENT_NO_SCHEMA"); }
    if bits & 0x00000020 != 0 { features.push("CLIENT_COMPRESS"); }
    if bits & 0x00000040 != 0 { features.push("CLIENT_ODBC"); }
    if bits & 0x00000080 != 0 { features.push("CLIENT_LOCAL_FILES"); }
    if bits & 0x00000100 != 0 { features.push("CLIENT_IGNORE_SPACE"); }
    if bits & 0x00000800 != 0 { features.push("CLIENT_PROTOCOL_41"); }
    if bits & 0x00002000 != 0 { features.push("CLIENT_SSL"); }
    if bits & 0x00008000 != 0 { features.push("CLIENT_TRANSACTIONS"); }
    if bits & 0x00020000 != 0 { features.push("CLIENT_MULTI_RESULTS"); }
    if bits & 0x00080000 != 0 { features.push("CLIENT_PLUGIN_AUTH"); }
    if bits & 0x00100000 != 0 { features.push("CLIENT_CONNECT_ATTRS"); }
    if bits & 0x80000000 != 0 { features.push("CLIENT_SESSION_TRACK"); }
    features
}

