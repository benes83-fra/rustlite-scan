use tokio::{io::{AsyncReadExt, AsyncWriteExt}, time::{Duration, timeout}};
use crate::{probes::{Probe, ProbeContext, helper::{connect_with_timeout, push_line}}, service::ServiceFingerprint};
use bson::{doc, Document};
use serde_json::from_slice;
use byteorder::{LittleEndian, WriteBytesExt};
pub struct MongoProbe;

#[async_trait::async_trait]
impl Probe for MongoProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let mut evidence = String::new();
        let timeout_dur = Duration::from_millis(timeout_ms);

        let mut tcp = match connect_with_timeout(ip, port, timeout_ms).await {
            Some(s) => s,
            None => {
                push_line(&mut evidence, "mongodb", "connect_timeout");
                return Some(ServiceFingerprint::from_banner(ip, port, "mongodb", evidence));
            }
        };

        // Build minimal OP_MSG with { hello: 1 }
        let hello_cmd = build_hello_opmsg();

        if timeout(timeout_dur, tcp.write_all(&hello_cmd)).await.is_err() {
            push_line(&mut evidence, "mongodb", "write_error");
            return Some(ServiceFingerprint::from_banner(ip, port, "mongodb", evidence));
        }

        let mut buf = vec![0u8; 8192];
        match timeout(timeout_dur, tcp.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                if let Some(info) = parse_hello_response(&buf[..n]) {
                    if let Some(ver) = info.version {
                        push_line(&mut evidence, "mongodb_version", &ver);
                    }
                    push_line(&mut evidence, "mongodb_wire_version",
                        &format!("{}-{}", info.min_wire, info.max_wire));

                    if let Some(role) = info.role {
                        push_line(&mut evidence, "mongodb_role", &role);
                    }
                    if let Some(rs) = info.replset {
                        push_line(&mut evidence, "mongodb_replset", &rs);
                    }
                    if !info.features.is_empty() {
                        push_line(&mut evidence, "mongodb_features", &info.features.join(", "));
                    }
                } else {
                    push_line(&mut evidence, "mongodb", "parse_error");
                }
            }
            _ => {
                push_line(&mut evidence, "mongodb", "read_error");
            }
        }

        Some(ServiceFingerprint::from_banner(ip, port, "mongodb", evidence))
    }

    async fn probe_with_ctx(&self, ip: &str, port: u16, ctx: ProbeContext) -> Option<ServiceFingerprint> {
        self.probe(ip, port, ctx.get("timeout_ms").and_then(|s| s.parse::<u64>().ok()).unwrap_or(2000)).await
    }

    fn ports(&self) -> Vec<u16> { vec![27017] }
    fn name(&self) -> &'static str { "mongodb" }
}


use std::io::Cursor;


fn build_hello_opmsg() -> Vec<u8> {
    // BSON document: { "hello": 1 }
    let body = bson::to_vec(&doc! { "hello": 1 }).unwrap();

    let mut msg = Vec::with_capacity(16 + 1 + 1 + body.len());

    // Placeholder for messageLength
    msg.extend_from_slice(&[0u8; 4]);

    // requestID
    WriteBytesExt::write_i32::<LittleEndian>(&mut msg, 1).unwrap();
    WriteBytesExt::write_i32::<LittleEndian>(&mut msg, 0).unwrap();
    WriteBytesExt::write_i32::<LittleEndian>(&mut msg, 2013).unwrap();
    WriteBytesExt::write_u8(&mut msg, 0).unwrap();
    WriteBytesExt::write_u8(&mut msg, 0).unwrap();


    // BSON body
    msg.extend_from_slice(&body);

    // Now fill in messageLength
    let len = msg.len() as i32;
    let mut cursor = Cursor::new(&mut msg[..4]);
    WriteBytesExt::write_i32::<LittleEndian>(&mut cursor, len).unwrap();

    msg
}



#[derive(Debug)]
pub struct MongoHelloInfo {
    pub version: Option<String>,
    pub min_wire: i32,
    pub max_wire: i32,
    pub role: Option<String>,
    pub replset: Option<String>,
    pub features: Vec<String>,
}

fn parse_hello_response(buf: &[u8]) -> Option<MongoHelloInfo> {
    if buf.len() < 20 {
        return None;
    }

    // Skip header (16 bytes) + flags (1) + section kind (1)
    let bson_start = 18;
    if bson_start >= buf.len() {
        return None;
    }

    let doc: Document = bson::from_slice(&buf[bson_start..]).ok()?;

    let version = doc.get_str("version").ok().map(|s| s.to_string());
    let min_wire = doc.get_i32("minWireVersion").unwrap_or(0);
    let max_wire = doc.get_i32("maxWireVersion").unwrap_or(0);

    let role = if let Ok(msg) = doc.get_str("msg") {
        if msg == "isdbgrid" {
            Some("mongos".into())
        } else {
            None
        }
    } else if doc.get_bool("isWritablePrimary").unwrap_or(false) {
        Some("primary".into())
    } else {
        Some("secondary".into())
    };

    let replset = doc.get_str("setName").ok().map(|s| s.to_string());

    let mut features = Vec::new();
    if doc.get("logicalSessionTimeoutMinutes").is_some() {
        features.push("sessions".into());
    }
    if doc.get_bool("supportsTransactions").unwrap_or(false) {
        features.push("transactions".into());
    }
    if doc.get_bool("retryableWrites").unwrap_or(false) {
        features.push("retryable_writes".into());
    }
    if let Ok(mods) = doc.get_array("modules") {
        for m in mods {
            if let Some(s) = m.as_str() {
                features.push(format!("module:{}", s));
            }
        }
    }

    Some(MongoHelloInfo {
        version,
        min_wire,
        max_wire,
        role,
        replset,
        features,
    })
}

