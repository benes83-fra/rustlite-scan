use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    time::{timeout, Duration},
};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::collections::HashMap;
use std::io::{Cursor, Read};

use crate::{
    probes::{Probe, ProbeContext, helper::{connect_with_timeout, push_line}},
    service::ServiceFingerprint,
};

pub struct KafkaProbe;

#[async_trait::async_trait]
impl Probe for KafkaProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let timeout_dur = Duration::from_millis(timeout_ms);
        let mut evidence = String::new();
        let mut confidence: u8 = 50;

        // Connect helper (reused for ApiVersions attempts)
        let mut tcp = match connect_with_timeout(ip, port, timeout_ms).await {
            Some(s) => s,
            None => {
                push_line(&mut evidence, "kafka", "connect_timeout");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "kafka", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        // Try ApiVersions across a few versions (3 first, then 0..=2)
        let initial_versions = [3i16, 0, 1, 2];
        for &ver in &initial_versions {
            let req = build_kafka_request(18, ver, 1, "rust-scan", &[]);
            if timeout(timeout_dur, tcp.write_all(&req)).await.is_err() {
                tcp = match connect_with_timeout(ip, port, timeout_ms).await {
                    Some(s) => s,
                    None => break,
                };
                continue;
            }

            // Read length prefix
            let mut len_buf = [0u8; 4];
            if read_exact_timeout(&mut tcp, &mut len_buf, timeout_dur).await.is_none() {
                tcp = match connect_with_timeout(ip, port, timeout_ms).await {
                    Some(s) => s,
                    None => break,
                };
                continue;
            }

            let len = i32::from_be_bytes(len_buf) as usize;
            if len == 0 {
                tcp = match connect_with_timeout(ip, port, timeout_ms).await {
                    Some(s) => s,
                    None => break,
                };
                continue;
            }

            if len > 10_000_000 {
                push_line(&mut evidence, "kafka", "invalid_length");
                break;
            }

            let mut payload = vec![0u8; len];
            if read_exact_timeout(&mut tcp, &mut payload, timeout_dur).await.is_none() {
                tcp = match connect_with_timeout(ip, port, timeout_ms).await {
                    Some(s) => s,
                    None => break,
                };
                continue;
            }

            // debug: raw ApiVersions payload
           

            if let Some(map) = parse_api_versions_response(&payload) {
                
                // Pretty-print and filter invalid entries, push evidence, bump confidence
                if !map.is_empty() {
                    // Filter out entries where min > max (likely parser artifacts)
                    let mut entries: Vec<(i16, i16, i16)> = map.iter()
                        .filter_map(|(&k, &(min, max))| {
                            if min <= max { Some((k, min, max)) } else { None }
                        })
                        .map(|(k, min, max)| (k, min, max))
                        .collect();

                    entries.sort_by_key(|e| e.0);

                    // Map common API keys to friendly names
                    fn api_name(key: i16) -> &'static str {
                        match key {
                            0 => "Produce",
                            1 => "Fetch",
                            2 => "ListOffsets",
                            3 => "Metadata",
                            5 => "OffsetCommit",
                            7 => "JoinGroup",
                            8 => "Heartbeat",
                            17 => "SaslHandshake",
                            18 => "ApiVersions",
                            19 => "CreateTopics",
                            20 => "DeleteTopics",
                            21 => "DeleteRecords",
                            22 => "InitProducerId",
                            23 => "OffsetForLeaderEpoch",
                            24 => "AddPartitionsToTxn",
                            25 => "AddOffsetsToTxn",
                            26 => "EndTxn",
                            27 => "WriteTxnMarkers",
                            28 => "TxnOffsetCommit",
                            29 => "DescribeAcls",
                            30 => "CreateAcls",
                            31 => "DeleteAcls",
                            32 => "DescribeConfigs",
                            33 => "AlterConfigs",
                            34 => "AlterReplicaLogDirs",
                            35 => "DescribeLogDirs",
                            36 => "SaslAuthenticate",
                            37 => "CreatePartitions",
                            38 => "CreateDelegationToken",
                            39 => "RenewDelegationToken",
                            40 => "ExpireDelegationToken",
                            41 => "DescribeDelegationToken",
                            42 => "DeleteGroups",
                            43 => "ElectLeaders",
                            _ => "Unknown",
                        }
                    }

                    let numeric = entries.iter()
                        .map(|(k, min, max)| format!("{}:{}-{}", k, min, max))
                        .collect::<Vec<_>>()
                        .join(", ");

                    let friendly = entries.iter()
                        .map(|(k, min, max)| {
                            let name = api_name(*k);
                            if name == "Unknown" {
                                format!("{}:{}-{}", k, min, max)
                            } else {
                                format!("{}({}):{}-{}", k, name, min, max)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ");

                    push_line(&mut evidence, "kafka", "api_versions");
                    push_line(&mut evidence, "kafka_api_versions", &numeric);
                    push_line(&mut evidence, "kafka_api_versions_friendly", &friendly);

                    // Bump confidence when ApiVersions is present
                    confidence = 75;
                    let mut fp = ServiceFingerprint::from_banner(ip, port, "kafka", evidence);
                    fp.confidence = confidence;
                    return Some(fp);
                }

                // Build fingerprint and return with updated confidence
                //let mut fp = ServiceFingerprint::from_banner(ip, port, "kafka", evidence);
                //fp.confidence = confidence;
                //return Some(fp);
            }

            // reconnect before next attempt
            tcp = match connect_with_timeout(ip, port, timeout_ms).await {
                Some(s) => s,
                None => break,
            };
        }

        // Fallback: reconnect and send Metadata request (api_key = 3)
        let mut tcp2 = match connect_with_timeout(ip, port, timeout_ms).await {
            Some(s) => s,
            None => {
                push_line(&mut evidence, "kafka", "connect_timeout");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "kafka", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        let metadata_body = metadata_request_body();
        let metadata_req = build_kafka_request(3, 0, 2, "rust-scan", &metadata_body);
        if timeout(timeout_dur, tcp2.write_all(&metadata_req)).await.is_err() {
            push_line(&mut evidence, "kafka", "write_error");
            let mut fp = ServiceFingerprint::from_banner(ip, port, "kafka", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }

        // Read metadata response length + payload
        let mut len_buf = [0u8; 4];
        if read_exact_timeout(&mut tcp2, &mut len_buf, timeout_dur).await.is_none() {
            push_line(&mut evidence, "kafka", "read_error");
            let mut fp = ServiceFingerprint::from_banner(ip, port, "kafka", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }
        let len = i32::from_be_bytes(len_buf) as usize;
        if len == 0 {
            push_line(&mut evidence, "kafka", "empty_response");
            let mut fp = ServiceFingerprint::from_banner(ip, port, "kafka", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }
        if len > 10_000_000 {
            push_line(&mut evidence, "kafka", "invalid_length");
            let mut fp = ServiceFingerprint::from_banner(ip, port, "kafka", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }

        let mut payload = vec![0u8; len];
        if read_exact_timeout(&mut tcp2, &mut payload, timeout_dur).await.is_none() {
            push_line(&mut evidence, "kafka", "read_error");
            let mut fp = ServiceFingerprint::from_banner(ip, port, "kafka", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }

        // debug: show raw metadata payload as hex AFTER we've read it
        eprintln!("kafka metadata payload len={} hex={}", payload.len(),
            payload.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""));

        // Minimal metadata parsing: correlation id, brokers array, optional cluster_id/controller_id
        let mut cursor = Cursor::new(&payload[..]);

        let _corr = ReadBytesExt::read_i32::<BigEndian>(&mut cursor).ok()?;
        let broker_count = ReadBytesExt::read_i32::<BigEndian>(&mut cursor).ok()?;
        let mut brokers: Vec<String> = Vec::new();

        for _ in 0..broker_count {
            let node_id = ReadBytesExt::read_i32::<BigEndian>(&mut cursor).ok()?;
            let host_len = ReadBytesExt::read_i16::<BigEndian>(&mut cursor).ok()? as usize;
            let mut host_bytes = vec![0u8; host_len];
            std::io::Read::read_exact(&mut cursor, &mut host_bytes).ok()?;
            let host = String::from_utf8_lossy(&host_bytes).to_string();
            let port = ReadBytesExt::read_i32::<BigEndian>(&mut cursor).ok()?;
            brokers.push(format!("{}:{} (id={})", host, port, node_id));
        }

        // Robust cluster_id + controller_id parsing (safe, conservative)
        let mut cluster_id: Option<String> = None;
        let mut controller_id: Option<i32> = None;

        let remaining = (cursor.get_ref().len() as i64) - (cursor.position() as i64);

        if remaining == 4 {
            if let Ok(cid) = ReadBytesExt::read_i32::<BigEndian>(&mut cursor) {
                controller_id = Some(cid);
            }
        } else if remaining >= 2 {
            let pos_before = cursor.position();
            if let Ok(len16) = ReadBytesExt::read_i16::<BigEndian>(&mut cursor) {
                if len16 >= 0 {
                    let mut cbytes = vec![0u8; len16 as usize];
                    if std::io::Read::read_exact(&mut cursor, &mut cbytes).is_ok() {
                        cluster_id = Some(String::from_utf8_lossy(&cbytes).to_string());
                    }
                } else {
                    cluster_id = None;
                }

                let rem_after = (cursor.get_ref().len() as i64) - (cursor.position() as i64);
                if rem_after >= 4 {
                    if let Ok(cid) = ReadBytesExt::read_i32::<BigEndian>(&mut cursor) {
                        controller_id = Some(cid);
                    }
                }
            } else {
                cursor.set_position(pos_before);
                if (cursor.get_ref().len() as i64) - (cursor.position() as i64) >= 4 {
                    if let Ok(len32) = ReadBytesExt::read_i32::<BigEndian>(&mut cursor) {
                        if len32 >= 0 {
                            let mut cbytes = vec![0u8; len32 as usize];
                            if std::io::Read::read_exact(&mut cursor, &mut cbytes).is_ok() {
                                cluster_id = Some(String::from_utf8_lossy(&cbytes).to_string());
                            }
                        }
                        let rem_after = (cursor.get_ref().len() as i64) - (cursor.position() as i64);
                        if rem_after >= 4 {
                            if let Ok(cid) = ReadBytesExt::read_i32::<BigEndian>(&mut cursor) {
                                controller_id = Some(cid);
                            }
                        }
                    }
                }
            }
        }

        if let Some(ref cid) = cluster_id {
            eprintln!("kafka: parsed cluster_id = {}", cid);
        } else {
            eprintln!("kafka: no cluster_id present in metadata (likely Metadata v0)");
        }
        if let Some(ctrl) = controller_id {
            eprintln!("kafka: parsed controller_id = {}", ctrl);
        }

        push_line(&mut evidence, "kafka", "metadata_response");
        push_line(&mut evidence, "kafka_brokers", &brokers.join(", "));
        if let Some(cid) = cluster_id { push_line(&mut evidence, "kafka_cluster_id", cid.as_str()); }
        if let Some(ctrl) = controller_id { push_line(&mut evidence, "kafka_controller_id", &ctrl.to_string()); }

        // Return fingerprint with confidence
        let mut fp = ServiceFingerprint::from_banner(ip, port, "kafka", evidence);
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

    fn ports(&self) -> Vec<u16> { vec![9092] }
    fn name(&self) -> &'static str { "kafka" }
}

// ----------------- helper functions -----------------

fn build_kafka_request(api_key: i16, api_version: i16, correlation_id: i32, client_id: &str, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    WriteBytesExt::write_i16::<BigEndian>(&mut payload, api_key).unwrap();
    WriteBytesExt::write_i16::<BigEndian>(&mut payload, api_version).unwrap();
    WriteBytesExt::write_i32::<BigEndian>(&mut payload, correlation_id).unwrap();
    WriteBytesExt::write_i16::<BigEndian>(&mut payload, client_id.len() as i16).unwrap();
    payload.extend_from_slice(client_id.as_bytes());
    payload.extend_from_slice(body);
    let mut frame = Vec::new();
    WriteBytesExt::write_i32::<BigEndian>(&mut frame, payload.len() as i32).unwrap();
    frame.extend_from_slice(&payload);
    frame
}

async fn read_exact_timeout(tcp: &mut (impl AsyncRead + Unpin), buf: &mut [u8], timeout_dur: Duration) -> Option<()> {
    let mut read = 0usize;
    while read < buf.len() {
        let n = match timeout(timeout_dur, tcp.read(&mut buf[read..])).await {
            Ok(Ok(n)) => n,
            _ => return None,
        };
        if n == 0 { return None; }
        read += n;
    }
    Some(())
}

fn parse_api_versions_response(payload: &[u8]) -> Option<HashMap<i16, (i16, i16)>> {
    use std::io::Cursor;
    use byteorder::{BigEndian, ReadBytesExt};

    // read uvarint by advancing cursor
    fn read_uvarint(cursor: &mut Cursor<&[u8]>) -> Option<u64> {
        let mut x: u64 = 0;
        let mut s: u32 = 0;
        loop {
            let idx = cursor.position() as usize;
            let b = *cursor.get_ref().get(idx)?;
            cursor.set_position(cursor.position() + 1);
            if b < 0x80 {
                if s >= 64 { return None; }
                return Some(x | ((b as u64) << s));
            }
            x |= ((b & 0x7F) as u64) << s;
            s += 7;
            if s >= 64 { return None; }
        }
    }

    // peek uvarint from a slice at offset without advancing any cursor
    fn peek_uvarint(slice: &[u8], mut off: usize) -> Option<(u64, usize)> {
        let mut x: u64 = 0;
        let mut s: u32 = 0;
        let mut read = 0usize;
        loop {
            let b = *slice.get(off)?;
            off += 1;
            read += 1;
            if b < 0x80 {
                if s >= 64 { return None; }
                return Some((x | ((b as u64) << s), read));
            }
            x |= ((b & 0x7F) as u64) << s;
            s += 7;
            if s >= 64 { return None; }
        }
    }

    // skip tagged fields using cursor
    fn skip_tagged(cursor: &mut Cursor<&[u8]>) -> Option<()> {
        let num = read_uvarint(cursor)?;
        for _ in 0..num {
            let _tag = read_uvarint(cursor)?;
            let size = read_uvarint(cursor)?;
            let new_pos = cursor.position() + size;
            if new_pos > cursor.get_ref().len() as u64 { return None; }
            cursor.set_position(new_pos);
        }
        Some(())
    }

    // --- 1) Try flexible detection safely ---
    let flexible_map_opt: Option<HashMap<i16, (i16, i16)>> = {
        let mut cursor = Cursor::new(payload);

        // correlation_id + throttle_time_ms are present in both formats
        let _corr = ReadBytesExt::read_i32::<BigEndian>(&mut cursor).ok()?;
        let _throttle = ReadBytesExt::read_i32::<BigEndian>(&mut cursor).ok()?;

        // position where next field would start
        let pos_next = cursor.position() as usize;

        if payload.len() >= pos_next + 3 {
            if let Some((count_peek, _uvarint_len)) = peek_uvarint(payload, pos_next + 2) {
                if count_peek > 0 && count_peek <= 100_000 {
                    cursor.set_position(pos_next as u64);
                    let _err = ReadBytesExt::read_i16::<BigEndian>(&mut cursor).ok()?;
                    let count = read_uvarint(&mut cursor)? as usize;
                    if count <= 100_000 {
                        let mut map = HashMap::new();
                        for _ in 0..count {
                            let api_key = ReadBytesExt::read_i16::<BigEndian>(&mut cursor).ok()?;
                            let min = ReadBytesExt::read_i16::<BigEndian>(&mut cursor).ok()?;
                            let max = ReadBytesExt::read_i16::<BigEndian>(&mut cursor).ok()?;
                            map.insert(api_key, (min, max));
                            skip_tagged(&mut cursor)?;
                        }
                        // skip top-level tagged fields
                        skip_tagged(&mut cursor)?;
                        if !map.is_empty() { return Some(map); } // flexible is authoritative if it parsed entries
                    }
                }
            }
        }
        None
    };

    // --- 2) Try canonical classic parsing at canonical offset (pos 8) ---
    let canonical_map_opt: Option<HashMap<i16, (i16, i16)>> = {
        let mut cursor = Cursor::new(payload);

        let _corr = ReadBytesExt::read_i32::<BigEndian>(&mut cursor).ok()?;
        let _throttle = ReadBytesExt::read_i32::<BigEndian>(&mut cursor).ok()?;

        let count = ReadBytesExt::read_i32::<BigEndian>(&mut cursor).ok()? as usize;

        // sanity checks: count reasonable and fits payload
        if count <= 100_000 && (8usize + count * 6) <= payload.len() {
            let mut map = HashMap::new();
            for _ in 0..count {
                let api_key = ReadBytesExt::read_i16::<BigEndian>(&mut cursor).ok()?;
                let min = ReadBytesExt::read_i16::<BigEndian>(&mut cursor).ok()?;
                let max = ReadBytesExt::read_i16::<BigEndian>(&mut cursor).ok()?;
                map.insert(api_key, (min, max));
            }
            if !map.is_empty() { return Some(map); }
        }
        None
    };

    // --- 3) Heuristic scan: try small range of offsets to find plausible triples ---
    let scanned_map_opt: Option<HashMap<i16, (i16, i16)>> = {
        let mut best_map: HashMap<i16, (i16, i16)> = HashMap::new();
        let mut best_count = 0usize;

        for start in 8usize..=12usize {
            if payload.len() <= start + 4 { continue; }
            // try to read a 4-byte BE count at this start
            let maybe_count = i32::from_be_bytes([
                *payload.get(start)?,
                *payload.get(start + 1)?,
                *payload.get(start + 2)?,
                *payload.get(start + 3)?,
            ]) as isize;

            if maybe_count >= 0 && (start + (maybe_count as usize) * 6) <= payload.len() && (maybe_count as usize) <= 100_000 {
                let mut map = HashMap::new();
                let mut ok = true;
                let mut off = start + 4;
                for _ in 0..(maybe_count as usize) {
                    if off + 6 > payload.len() { ok = false; break; }
                    let api_key = i16::from_be_bytes([payload[off], payload[off + 1]]);
                    let min = i16::from_be_bytes([payload[off + 2], payload[off + 3]]);
                    let max = i16::from_be_bytes([payload[off + 4], payload[off + 5]]);
                    off += 6;
                    if min > max { ok = false; break; }
                    if api_key < 0 || api_key > 200 { ok = false; break; }
                    map.insert(api_key, (min, max));
                }
                if ok && map.len() > best_count {
                    best_count = map.len();
                    best_map = map;
                }
            } else {
                // greedy triple scan from start
                let mut map = HashMap::new();
                let mut off = start;
                let mut triples = 0usize;
                while off + 6 <= payload.len() && triples < 1000 {
                    let api_key = i16::from_be_bytes([payload[off], payload[off + 1]]);
                    let min = i16::from_be_bytes([payload[off + 2], payload[off + 3]]);
                    let max = i16::from_be_bytes([payload[off + 4], payload[off + 5]]);
                    if min <= max && api_key >= 0 && api_key <= 200 {
                        map.insert(api_key, (min, max));
                        triples += 1;
                        off += 6;
                    } else {
                        break;
                    }
                }
                if triples > best_count {
                    best_count = triples;
                    best_map = map;
                }
            }
        }

        if best_count > 0 { Some(best_map) } else { None }
    };

    // --- Merge results: prefer canonical, then flexible, then scanned ---
    let mut merged: HashMap<i16, (i16, i16)> = HashMap::new();

    if let Some(canon) = canonical_map_opt {
        for (k, v) in canon.into_iter() { merged.insert(k, v); }
    }

    if let Some(flex) = flexible_map_opt {
        for (k, v) in flex.into_iter() {
            merged.entry(k).or_insert(v);
        }
    }

    if let Some(scan) = scanned_map_opt {
        for (k, v) in scan.into_iter() {
            merged.entry(k).or_insert(v);
        }
    }

    if merged.is_empty() { None } else { Some(merged) }
}






fn metadata_request_body() -> Vec<u8> {
    let mut b = Vec::new();
    WriteBytesExt::write_i32::<BigEndian>(&mut b, 0).unwrap(); // topics array length = 0
    b
}
