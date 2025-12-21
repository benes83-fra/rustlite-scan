use tokio::{io::{AsyncReadExt, AsyncWriteExt}, time::{Duration, timeout}};
use crate::{probes::{Probe, ProbeContext, helper::{connect_with_timeout, push_line}}, service::ServiceFingerprint};
use bson::{doc, Document};

use std::io::Cursor;
use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};
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

       
        let msg = match read_mongo_message(&mut tcp, timeout_dur).await {
                    Some(m) => m,
                    None => { push_line(&mut evidence, "mongodb", "read_error"); 
                    return Some(ServiceFingerprint::from_banner(ip, port, "mongodb", evidence)); }
                };
        let mut info = parse_hello_response(&msg);


        // If hello returned no wire info (max_wire == 0), fallback to isMaster
        let need_fallback = match &info {
            Some(i) => i.max_wire == 0 && i.min_wire == 0,
            None => true,
        };

        if need_fallback {
            // send isMaster
            let ismaster_cmd = build_ismaster_opmsg();
            if timeout(timeout_dur, tcp.write_all(&ismaster_cmd)).await.is_err() {
                push_line(&mut evidence, "mongodb", "write_error");
                return Some(ServiceFingerprint::from_banner(ip, port, "mongodb", evidence));
            }

            // read fallback response
            let msg2 = match read_mongo_message(&mut tcp, timeout_dur).await {
                Some(m) => m,
                None => {
                    push_line(&mut evidence, "mongodb", "read_error");
                    return Some(ServiceFingerprint::from_banner(ip, port, "mongodb", evidence));
                }
            };
            info = parse_hello_response(&msg2);
        }

        // Now process whatever info we have (could still be None)
        if let Some(info) = info {
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
        Some(ServiceFingerprint::from_banner(ip, port, "mongodb", evidence))
    }

    async fn probe_with_ctx(&self, ip: &str, port: u16, ctx: ProbeContext) -> Option<ServiceFingerprint> {
        self.probe(ip, port, ctx.get("timeout_ms").and_then(|s| s.parse::<u64>().ok()).unwrap_or(2000)).await
    }

    fn ports(&self) -> Vec<u16> { vec![27017] }
    fn name(&self) -> &'static str { "mongodb" }
}

async fn read_mongo_message(
    tcp: &mut (impl AsyncReadExt + Unpin),
    timeout_dur: Duration,
) -> Option<Vec<u8>> {
    // read first 4 bytes (messageLength)
    let mut len_buf = [0u8; 4];
    if timeout(timeout_dur, tcp.read_exact(&mut len_buf)).await.is_err() {
        return None;
    }
    let total_len = LittleEndian::read_i32(&len_buf) as usize;
    if total_len < 16 {
        return None;
    }

    // we already read 4 bytes, now read the remaining total_len - 4 bytes
    let mut rest = vec![0u8; total_len - 4];
    if timeout(timeout_dur, tcp.read_exact(&mut rest)).await.is_err() {
        return None;
    }

    // combine
    let mut msg = Vec::with_capacity(total_len);
    msg.extend_from_slice(&len_buf);
    msg.extend_from_slice(&rest);
    Some(msg)
}


fn build_hello_opmsg() -> Vec<u8> {
    // BSON document: { "hello": 1, "helloOk": true }
    let body = bson::to_vec(&doc! { "hello": 1, "helloOk": true, "$db": "admin" }).unwrap();


    let mut msg = Vec::with_capacity(16 + 4 + 1 + body.len());

    // Placeholder for messageLength
    msg.extend_from_slice(&[0u8; 4]);

    // requestID
    WriteBytesExt::write_i32::<LittleEndian>(&mut msg, 1).unwrap();

    // responseTo
    WriteBytesExt::write_i32::<LittleEndian>(&mut msg, 0).unwrap();

    // opCode = 2013 (OP_MSG)
    WriteBytesExt::write_i32::<LittleEndian>(&mut msg, 2013).unwrap();

    // flags (uint32)
    WriteBytesExt::write_u32::<LittleEndian>(&mut msg, 0).unwrap();

    // section kind (uint8)
    WriteBytesExt::write_u8(&mut msg, 0).unwrap();

    // BSON body
    msg.extend_from_slice(&body);

    // Now fill in messageLength
    let len = msg.len() as i32;
    let mut cursor = Cursor::new(&mut msg[..4]);
    WriteBytesExt::write_i32::<LittleEndian>(&mut cursor, len).unwrap();

    msg
}


fn build_ismaster_opmsg() -> Vec<u8> {
    let body = bson::to_vec(&doc! { "isMaster": 1, "$db": "admin" }).unwrap();


    let mut msg = Vec::with_capacity(16 + 4 + 1 + body.len());

    // Placeholder for messageLength
    msg.extend_from_slice(&[0u8; 4]);

    // requestID
    WriteBytesExt::write_i32::<LittleEndian>(&mut msg, 2).unwrap();

    // responseTo
    WriteBytesExt::write_i32::<LittleEndian>(&mut msg, 0).unwrap();

    // opCode = 2013 (OP_MSG)
    WriteBytesExt::write_i32::<LittleEndian>(&mut msg, 2013).unwrap();

    // flags (uint32)
    WriteBytesExt::write_u32::<LittleEndian>(&mut msg, 0).unwrap();

    // section kind (uint8)
    WriteBytesExt::write_u8(&mut msg, 0).unwrap();

    // BSON body
    msg.extend_from_slice(&body);

    // Fill in messageLength
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
    if buf.len() < 16 {
        return None;
    }

    // header
    let message_length = LittleEndian::read_i32(&buf[0..4]) as usize;
    if message_length != buf.len() {
        // message incomplete or extra bytes; require exact match
        return None;
    }

    // opCode at bytes 12..16
    let op_code = LittleEndian::read_i32(&buf[12..16]);

    let mut doc_opt: Option<Document> = None;

    if op_code == 2013 {
        // OP_MSG
        if buf.len() < 21 {
            return None;
        }
        // flags: 4 bytes at offset 16..20
        let _flags = LittleEndian::read_u32(&buf[16..20]);
        // section kind at offset 20
        let kind = buf[20];
        match kind {
            0 => {
                // single BSON document starts at offset 21
                let bson_start = 21;
                if bson_start + 4 > buf.len() {
                    return None;
                }
                let bson_size = LittleEndian::read_i32(&buf[bson_start..bson_start + 4]) as usize;
                if bson_start + bson_size > buf.len() {
                    return None;
                }
                doc_opt = bson::from_slice(&buf[bson_start..bson_start + bson_size]).ok();
            }
            1 => {
                // kind 1: int32 size, then sequence of documents. size is at offset 21..25
                if buf.len() < 25 {
                    return None;
                }
                let size = LittleEndian::read_i32(&buf[21..25]) as usize;
                if 21 + size > buf.len() {
                    return None;
                }
                // first document in the sequence starts at 25
                let pos = 25usize;
                if pos + 4 > buf.len() {
                    return None;
                }
                let first_doc_size = LittleEndian::read_i32(&buf[pos..pos + 4]) as usize;
                if pos + first_doc_size > buf.len() {
                    return None;
                }
                doc_opt = bson::from_slice(&buf[pos..pos + first_doc_size]).ok();
            }
            _ => return None,
        }
    } else if op_code == 1 {
        // OP_REPLY (legacy): header(16) + responseFlags(4) + cursorID(8) + startingFrom(4) + numberReturned(4) + documents...
        // documents start at offset 36
        if buf.len() < 36 + 4 {
            return None;
        }
        let doc_start = 36usize;
        if doc_start + 4 > buf.len() {
            return None;
        }
        let first_doc_size = LittleEndian::read_i32(&buf[doc_start..doc_start + 4]) as usize;
        if doc_start + first_doc_size > buf.len() {
            return None;
        }
        doc_opt = bson::from_slice(&buf[doc_start..doc_start + first_doc_size]).ok();
    } else {
        // unknown op code — not handled
        return None;
    }

    let doc = doc_opt?;

    // TEMP DEBUG: uncomment to inspect the actual reply document while tuning
     //println!("mongo hello doc: {:?}", doc);

    // Extract fields (hello or isMaster style)
    let version = doc.get_str("version")
        .or_else(|_| doc.get_str("mongodbVersion"))
        .ok()
        .map(|s| s.to_string());

    let min_wire = doc.get_i32("minWireVersion")
        .or_else(|_| doc.get_i32("minWireVersionInternal"))
        .unwrap_or(0);

    let max_wire = doc.get_i32("maxWireVersion")
        .or_else(|_| doc.get_i32("maxWireVersionInternal"))
        .unwrap_or(0);

    let role = if doc.get_bool("isWritablePrimary").unwrap_or(false)
        || doc.get_bool("ismaster").unwrap_or(false)
    {
        Some("primary".into())
    } else if doc.get_bool("secondary").unwrap_or(false) {
        Some("secondary".into())
    } else if doc.get_str("msg").ok() == Some("isdbgrid") {
        Some("mongos".into())
    } else {
        Some("unknown".into())
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



