use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{Duration, timeout},
};
use crate::{
    probes::{Probe, ProbeContext, helper::{connect_with_timeout, push_line}},
    service::ServiceFingerprint,
};

use std::collections::HashMap;

pub struct RabbitMqProbe;

#[async_trait::async_trait]
impl Probe for RabbitMqProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let mut evidence = String::new();
        let timeout_dur = Duration::from_millis(timeout_ms);

        let mut tcp = match connect_with_timeout(ip, port, timeout_ms).await {
            Some(s) => s,
            None => {
                push_line(&mut evidence, "rabbitmq", "connect_timeout");
                return Some(ServiceFingerprint::from_banner(ip, port, "rabbitmq", evidence));
            }
        };
        let header = b"AMQP\x00\x00\x09\x01";
        tcp.write_all(header).await.ok()?;

        // RabbitMQ sends Connection.Start immediately; we just read one frame.
        let frame = match read_amqp_frame(&mut tcp, timeout_dur).await {
            Some(f) => f,
          None => {
                    // --- Fallback: try AMQP 1.0 ---
                    let mut tcp2 = match connect_with_timeout(ip, port, timeout_ms).await {
                        Some(s) => s,
                        None => {
                            push_line(&mut evidence, "rabbitmq", "connect_timeout");
                            return Some(ServiceFingerprint::from_banner(ip, port, "rabbitmq", evidence));
                        }
                    };

                    const AMQP_1_0_HEADER: &[u8] = b"AMQP\x00\x01\x00\x00";

                    // Send AMQP 1.0 header
                    if timeout(timeout_dur, tcp2.write_all(AMQP_1_0_HEADER)).await.is_ok() {
                        // Try to read the echoed header
                        let mut resp = [0u8; 8];
                        let mut read = 0;

                        while read < 8 {
                            let n = match timeout(timeout_dur, tcp2.read(&mut resp[read..])).await {
                                Ok(Ok(n)) => n,
                                _ => break,
                            };
                            if n == 0 {
                                break;
                            }
                            read += n;
                        }

                        if resp == AMQP_1_0_HEADER {
                            // --- AMQP 1.0 detected ---
                            push_line(&mut evidence, "amqp1.0", "protocol_header_accepted");

                            return Some(ServiceFingerprint::from_banner(
                                ip,
                                port,
                                "amqp1.0",
                                evidence,
                            ));
                        }
                    }

                    // If we reach here, AMQP 1.0 also failed
                    push_line(&mut evidence, "rabbitmq", "read_error");
                    return Some(ServiceFingerprint::from_banner(ip, port, "rabbitmq", evidence));
                }

        };

        // type 1 = METHOD
        if frame.frame_type != 1 {
            push_line(&mut evidence, "rabbitmq", "unexpected_frame_type");
            return Some(ServiceFingerprint::from_banner(ip, port, "rabbitmq", evidence));
        }

        if let Some(info) = parse_connection_start(&frame.payload) {
            if let Some(p) = info.product {
                push_line(&mut evidence, "rabbitmq_product", &p);
            }
            if let Some(v) = info.version {
                push_line(&mut evidence, "rabbitmq_version", &v);
            }
            if let Some(plat) = info.platform {
                push_line(&mut evidence, "rabbitmq_platform", &plat);
            }
            if let Some(cluster) = info.cluster_name {
                push_line(&mut evidence, "rabbitmq_cluster_name", &cluster);
            }
            if let Some(mech) = info.mechanisms {
                push_line(&mut evidence, "rabbitmq_mechanisms", &mech);
            }
            if let Some(loc) = info.locales {
                push_line(&mut evidence, "rabbitmq_locales", &loc);
            }
            if !info.capabilities.is_empty() {
                let caps = info.capabilities.join(", ");
                push_line(&mut evidence, "rabbitmq_capabilities", &caps);
            }
        } else {
            push_line(&mut evidence, "rabbitmq", "parse_error");
        }

        Some(ServiceFingerprint::from_banner(ip, port, "rabbitmq", evidence))
    }

    async fn probe_with_ctx(&self, ip: &str, port: u16, ctx: ProbeContext) -> Option<ServiceFingerprint> {
        self.probe(
            ip,
            port,
            ctx.get("timeout_ms")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(2000),
        )
        .await
    }

    fn ports(&self) -> Vec<u16> { vec![5672] }
    fn name(&self) -> &'static str { "rabbitmq" }
}

// =================== AMQP frame reading ===================

struct AmqpFrame {
    frame_type: u8,
    channel: u16,
    payload: Vec<u8>, // does NOT include frame-end 0xCE
}

async fn read_amqp_frame(
    tcp: &mut (impl AsyncReadExt + Unpin),
    timeout_dur: Duration,
) -> Option<AmqpFrame> {
    // AMQP frame header: type(1) + channel(2) + size(4) = 7 bytes
    let mut header = [0u8; 7];
    let mut read = 0;

    while read < 7 {
        let n = match timeout(timeout_dur, tcp.read(&mut header[read..])).await {
            Ok(Ok(n)) => n,
            
            _ => return None,
        };

        if n == 0 {
           
            return None; // connection closed early
        }

        read += n;
       
    }
  

    let frame_type = header[0];
    let channel = u16::from_be_bytes([header[1], header[2]]);
    let size = u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;

    // payload + frame-end(1)
    let mut buf = vec![0u8; size + 1];
    let mut read = 0;

    while read < buf.len() {
        let n = match timeout(timeout_dur, tcp.read(&mut buf[read..])).await {
            Ok(Ok(n)) => n,
            _ => return None,
        };

        if n == 0 {
            return None; // connection closed early
        }

        read += n;
    }

    // last byte must be 0xCE
    if buf[size] != 0xCE {
        return None;
    }

    let payload = buf[..size].to_vec();

    Some(AmqpFrame { frame_type, channel, payload })
}

// =================== AMQP field/value types ===================

#[derive(Debug, Clone)]
enum AmqpFieldValue {
    Str(String),
    Bool(bool),
    Int(),
    Table(AmqpTable),
    Null,
    // other AMQP types omitted (not needed for RabbitMQ Connection.Start)
}

type AmqpTable = HashMap<String, AmqpFieldValue>;

// =================== Connection.Start parsing ===================

#[derive(Debug)]
struct RabbitMqInfo {
    product: Option<String>,
    version: Option<String>,
    platform: Option<String>,
    cluster_name: Option<String>,
    mechanisms: Option<String>,
    locales: Option<String>,
    capabilities: Vec<String>,
}

fn parse_connection_start(payload: &[u8]) -> Option<RabbitMqInfo> {
    let mut off = 0usize;

    // class-id (2 bytes) = 10, method-id (2 bytes) = 10
    if payload.len() < 4 {
        return None;
    }
    let class_id = u16::from_be_bytes([payload[off], payload[off + 1]]);
    off += 2;
    let method_id = u16::from_be_bytes([payload[off], payload[off + 1]]);
    off += 2;

    if class_id != 10 || method_id != 10 {
        return None;
    }

    if payload.len() < off + 2 {
        return None;
    }

    let _version_major = payload[off];
    let _version_minor = payload[off + 1];
    off += 2;

    // server-properties table (strict)
    let (server_props, new_off) = parse_amqp_table_strict(payload, off)?;
    off = new_off;

    // mechanisms (long string)
    let (mechanisms, new_off) = parse_longstr(payload, off)?;
    off = new_off;

    // locales (long string)
    let (locales, _new_off) = parse_longstr(payload, off).unwrap_or((String::new(), off));

    // Extract top-level properties
    let mut product = None;
    let mut version = None;
    let mut platform = None;
    let mut cluster_name = None;
    let mut capabilities_vec = Vec::new();

    if let Some(AmqpFieldValue::Str(p)) = server_props.get("product") {
        product = Some(p.clone());
    }
    if let Some(AmqpFieldValue::Str(v)) = server_props.get("version") {
        version = Some(v.clone());
    }
    if let Some(AmqpFieldValue::Str(plat)) = server_props.get("platform") {
        platform = Some(plat.clone());
    }
    if let Some(AmqpFieldValue::Str(cn)) = server_props.get("cluster_name") {
        cluster_name = Some(cn.clone());
    }

    // capabilities: nested table, parsed leniently
    if let Some(AmqpFieldValue::Table(caps)) = server_props.get("capabilities") {
        // keys with true boolean -> capability names
        for (k, v) in caps {
            if let AmqpFieldValue::Bool(true) = v {
                capabilities_vec.push(k.clone());
            }
        }
        // sometimes cluster_name lives inside capabilities as well
        if cluster_name.is_none() {
            if let Some(AmqpFieldValue::Str(cn)) = caps.get("cluster_name") {
                cluster_name = Some(cn.clone());
            }
        }
    }

    Some(RabbitMqInfo {
        product,
        version,
        platform,
        cluster_name,
        mechanisms: if mechanisms.is_empty() { None } else { Some(mechanisms) },
        locales: if locales.is_empty() { None } else { Some(locales) },
        capabilities: capabilities_vec,
    })
}

// =================== AMQP primitives ===================

// longstr: 4-byte length (BE) + bytes
fn parse_longstr(buf: &[u8], off: usize) -> Option<(String, usize)> {
    if buf.len() < off + 4 {
        return None;
    }
    let len = u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
    let start = off + 4;
    let end = start + len;
    if buf.len() < end {
        return None;
    }
    let s = String::from_utf8_lossy(&buf[start..end]).to_string();
    Some((s, end))
}

// shortstr: 1-byte length + bytes
fn parse_shortstr(buf: &[u8], off: usize) -> Option<(String, usize)> {
    if buf.len() < off + 1 {
        return None;
    }
    let len = buf[off] as usize;
    let start = off + 1;
    let end = start + len;
    if buf.len() < end {
        return None;
    }
    let s = String::from_utf8_lossy(&buf[start..end]).to_string();
    Some((s, end))
}

// =================== AMQP table parsing ===================

// Strict top-level table: if anything is malformed, return None
fn parse_amqp_table_strict(buf: &[u8], off: usize) -> Option<(AmqpTable, usize)> {
    parse_amqp_table(buf, off, true)
}

// Generic table parser: `strict` controls behavior on unknown/invalid fields.
fn parse_amqp_table(buf: &[u8], off: usize, strict: bool) -> Option<(AmqpTable, usize)> {
    if buf.len() < off + 4 {
        return None;
    }

    let size = u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
    let mut cur = off + 4;
    let end = cur + size;
    if buf.len() < end {
        return None;
    }

    let mut table = AmqpTable::new();

    while cur < end {
        // key: shortstr
        let (key, key_off) = match parse_shortstr(buf, cur) {
            Some(v) => v,
            None => {
                if strict { return None; } else { break; }
            }
        };
        cur = key_off;

        if buf.len() < cur + 1 {
            if strict { return None; } else { break; }
        }
        let ftype = buf[cur];
        cur += 1;

        let (val, new_cur) = match ftype {
            b'S' => {
                // long string
                match parse_longstr(buf, cur) {
                    Some((s, n)) => (AmqpFieldValue::Str(s), n),
                    None => {
                        if strict { return None; } else { break; }
                    }
                }
            }
            b't' => {
                // boolean (1 byte)
                if buf.len() < cur + 1 {
                    if strict { return None; } else { break; }
                }
                let b = buf[cur] != 0;
                (AmqpFieldValue::Bool(b), cur + 1)
            }
            b'I' => {
                // 32-bit signed int
                if buf.len() < cur + 4 {
                    if strict { return None; } else { break; }
                }
                let _v = i32::from_be_bytes([buf[cur], buf[cur + 1], buf[cur + 2], buf[cur + 3]]);
                (AmqpFieldValue::Int(), cur + 4)
            }
            b'F' => {
                // nested table (lenient parsing inside)
                match parse_amqp_table(buf, cur, false) {
                    Some((t, n)) => (AmqpFieldValue::Table(t), n),
                    None => {
                        if strict { return None; } else { break; }
                    }
                }
            }
            b'V' => {
                // null
                (AmqpFieldValue::Null, cur)
            }
            // Unknown field type: skip or fail depending on strictness
            _other => {
                // In lenient mode, we stop parsing to avoid misalignment; in strict, fail.
                // You can enhance this with heuristics later.
                if strict {
                    // println!("Unknown AMQP field type: {}", other);
                    return None;
                } else {
                    // best-effort: stop parsing further fields
                    break;
                }
            }
        };

        cur = new_cur;
        table.insert(key, val);
    }

    Some((table, end))
}
