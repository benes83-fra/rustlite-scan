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
            eprintln!("kafka api_versions (ver={}) payload len={} hex={}", ver, payload.len(),
                payload.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""));

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
                }

                // Build fingerprint and return with updated confidence
                let mut fp = ServiceFingerprint::from_banner(ip, port, "kafka", evidence);
                fp.confidence = confidence;
                return Some(fp);
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


    let mut cursor = Cursor::new(payload);

    // correlation id
    let _corr = ReadBytesExt::read_i32::<BigEndian>(&mut cursor).ok()?;

    // throttle_time_ms (present in some response versions)
    let _throttle_time_ms = ReadBytesExt::read_i32::<BigEndian>(&mut cursor).ok()?;

    // array length (int32)
    let count = ReadBytesExt::read_i32::<BigEndian>(&mut cursor).ok()?;
    if count < 0 { return None; }

    let mut map = HashMap::new();

    for _ in 0..count {
        // ensure enough bytes remain for the minimal entry (6 bytes)
        let pos_before = cursor.position() as usize;
        let remaining = payload.len().saturating_sub(pos_before);
        if remaining < 6 {
            break;
        }

        // read canonical triple
        let api_key = ReadBytesExt::read_i16::<BigEndian>(&mut cursor).ok()?;
        let min_version = ReadBytesExt::read_i16::<BigEndian>(&mut cursor).ok()?;
        let max_version = ReadBytesExt::read_i16::<BigEndian>(&mut cursor).ok()?;

        map.insert(api_key, (min_version, max_version));

        // Attempt to skip optional per-entry suffixes conservatively.
        let pos_after = cursor.position() as usize;
        let rem_after = payload.len().saturating_sub(pos_after);

        if rem_after >= 4 {
            // peek next i32 and consume if it looks like a small non-negative length/flags
            let mut peek_buf = [0u8; 4];
            let cur_pos = cursor.position();
            if std::io::Read::read_exact(&mut cursor, &mut peek_buf).is_ok() {
                let maybe_i32 = i32::from_be_bytes(peek_buf);
                if !(maybe_i32 >= 0 && maybe_i32 <= 1_000_000) {
                    cursor.set_position(cur_pos);
                }
            } else {
                cursor.set_position(cur_pos);
            }
        } else if rem_after > 0 {
            // Try to skip a varint (tagged fields) conservatively (up to 5 bytes)
            let mut ok = false;
            let cur_pos = cursor.position();
            for _ in 0..5 {
                if (cursor.position() as usize) >= payload.len() { break; }
                let b = payload[cursor.position() as usize];
                cursor.set_position(cursor.position() + 1);
                if (b & 0x80) == 0 {
                    ok = true;
                    break;
                }
            }
            if !ok {
                cursor.set_position(cur_pos);
            }
        }
    }

    Some(map)
}

fn metadata_request_body() -> Vec<u8> {
    let mut b = Vec::new();
    WriteBytesExt::write_i32::<BigEndian>(&mut b, 0).unwrap(); // topics array length = 0
    b
}
