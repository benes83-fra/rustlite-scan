// src/probes/postgres.rs (or wherever your Postgres probe lives)
use crate::probes::helper::push_line;
use crate::probes::ProbeContext;
use crate::service::ServiceFingerprint;
use super::Probe;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct PostgresProbe;

#[async_trait::async_trait]
impl Probe for PostgresProbe {
    // keep existing probe() for compatibility; implement probe_with_ctx
    async fn probe_with_ctx(&self, ip: &str, _port: u16, ctx: ProbeContext) -> Option<ServiceFingerprint> {
        let mut evidence = String::new();

        // parse params from ctx.params
        let timeout_ms = ctx
            .get("timeout_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(2000);
        let timeout_dur = Duration::from_millis(timeout_ms);

        let probe_mode = ctx.get("probe_mode").map(|s| s.as_str()).unwrap_or("");
        let aggressive = probe_mode.eq_ignore_ascii_case("aggressive");

        let usernames: Vec<String> = ctx
            .get("usernames")
            .map(|s| s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect())
            .unwrap_or_else(|| vec!["postgres".into()]);

        let dbnames: Vec<String> = ctx
            .get("dbnames")
            .map(|s| s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect())
            .unwrap_or_else(|| vec!["postgres".into()]);

        let max_attempts = ctx
            .get("max_attempts")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(5);

        // attempt list: if not aggressive, try a single safe combo (first username/db)
        let mut attempts = Vec::new();
        if aggressive {
            for u in &usernames {
                for d in &dbnames {
                    attempts.push((u.clone(), d.clone()));
                    if attempts.len() as u32 >= max_attempts { break; }
                }
                if attempts.len() as u32 >= max_attempts { break; }
            }
        } else {
            attempts.push((usernames[0].clone(), dbnames[0].clone()));
        }

        // Try each attempt until we get useful info
        for (user, db) in attempts {
            // build startup message for this user/db
            let startup = build_startup_message_with_db(&user, &db);

            let addr = format!("{}:5432", ip);
            match timeout(timeout_dur, TcpStream::connect(&addr)).await {
                Ok(Ok(mut stream)) => {
                    // send startup
                    if let Err(e) = timeout(timeout_dur, stream.write_all(&startup)).await {
                        push_line(&mut evidence, "postgres", &format!("write_error: {}", e));
                        continue;
                    }

                    // read server messages and interpret
                    match read_server_messages_with_error_parsing(&mut stream, timeout_dur).await {
                        Ok(info) => {
                            if let Some(ref ver) = info.server_version {
                                push_line(&mut evidence, "postgres_version", &ver);
                            } else {
                                push_line(&mut evidence, "postgres_version", "unknown");
                            }
                            push_line(&mut evidence, "postgres_auth_required", &format!("{}", info.auth_required));
                            if let Some(proto) = info.protocol_version {
                                push_line(&mut evidence, "postgres_protocol_version", &format!("{}", proto));
                            }
                            // If we got server_version or auth_required=false, we can stop early
                            if info.server_version.is_some() || !info.auth_required {
                                break;
                            }
                        }
                        Err(e) => {
                            // include which user/db we tried for debugging (but avoid leaking secrets)
                            push_line(&mut evidence, "postgres_error", &format!("user={} db={} err={}", user, db, e));
                            // continue to next combo
                        }
                    }
                }
                Ok(Err(e)) => {
                    push_line(&mut evidence, "postgres", &format!("connect_error: {}", e));
                }
                Err(_) => {
                    push_line(&mut evidence, "postgres", "connect_timeout");
                }
            }
        }

        Some(ServiceFingerprint::from_banner(ip, 5432, "postgres", evidence))
    }

    // keep trait compatibility
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        // default shim: build a minimal ctx with timeout_ms
        let mut ctx = ProbeContext::default();
        ctx.insert("timeout_ms", timeout_ms.to_string());
        self.probe_with_ctx(ip, port, ctx).await
    }

    fn ports(&self) -> Vec<u16> { vec![5432] }
    fn name(&self) -> &'static str { "postgres" }
}

// --- helper types and functions ---

struct PgInfo {
    server_version: Option<String>,
    auth_required: bool,
    protocol_version: Option<u32>,
}

/// Build a StartupMessage including database and user
fn build_startup_message_with_db(user: &str, db: &str) -> Vec<u8> {
    // protocol 3.0
    let mut body = Vec::new();
    body.extend_from_slice(&0x00030000u32.to_be_bytes());
    body.extend_from_slice(b"user\0");
    body.extend_from_slice(user.as_bytes());
    body.push(0);
    body.extend_from_slice(b"database\0");
    body.extend_from_slice(db.as_bytes());
    body.push(0);
    body.push(0); // terminator

    let len = (4 + body.len()) as u32;
    let mut msg = Vec::with_capacity(len as usize);
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(&body);
    msg
}

/// Read server messages and parse ParameterStatus, Authentication, ErrorResponse, ReadyForQuery
async fn read_server_messages_with_error_parsing(stream: &mut TcpStream, to: Duration) -> Result<PgInfo, String> {
    let mut info = PgInfo { server_version: None, auth_required: false, protocol_version: None };
    let mut buf = BytesMut::with_capacity(4096);

    loop {
        // read first byte (type) or single-byte SSL reply
        let mut first = [0u8; 1];
        match timeout(to, stream.read_exact(&mut first)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("read error: {}", e)),
            Err(_) => return Err("read timeout".into()),
        }

        // SSL single-byte reply handling
        if first[0] == b'S' || first[0] == b'N' {
            return Err(format!("server requested SSL (reply={})", first[0] as char));
        }

        // read 4-byte length
        let mut lenb = [0u8; 4];
        match timeout(to, stream.read_exact(&mut lenb)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("read length error: {}", e)),
            Err(_) => return Err("read length timeout".into()),
        }

        let typ = first[0] as char;
        let len = u32::from_be_bytes(lenb) as usize;
        if len < 4 { return Err(format!("invalid message length {}", len)); }
        let payload_len = len - 4;
        let mut payload = vec![0u8; payload_len];
        match timeout(to, stream.read_exact(&mut payload)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("read payload error: {}", e)),
            Err(_) => return Err("payload read timeout".into()),
        }

        match typ {
            'R' => {
                // Authentication request: first 4 bytes = auth code
                if payload_len >= 4 {
                    let code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    info.auth_required = code != 0;
                } else {
                    info.auth_required = true;
                }
            }
            'S' => {
                // ParameterStatus: key\0value\0
                if let Some((k, v)) = parse_cstring_pair(&payload) {
                    if k == "server_version" {
                        info.server_version = Some(v);
                    }
                }
            }
            'E' => {
                // ErrorResponse: parse fields and return the human message 'M' if present
                if let Some(msg) = parse_error_response(&payload) {
                    return Err(format!("server error: {}", msg));
                } else {
                    return Err("server error (unknown)".into());
                }
            }
            'Z' => {
                // ReadyForQuery - end of startup
                break;
            }
            _ => {
                // ignore other types
            }
        }

        if info.server_version.is_some() {
            break;
        }
    }

    Ok(info)
}

/// parse key\0value\0 pair from ParameterStatus payload
fn parse_cstring_pair(buf: &[u8]) -> Option<(String, String)> {
    if let Some(pos) = buf.iter().position(|&b| b == 0) {
        let key = String::from_utf8_lossy(&buf[..pos]).to_string();
        let rest = &buf[pos+1..];
        if let Some(pos2) = rest.iter().position(|&b| b == 0) {
            let val = String::from_utf8_lossy(&rest[..pos2]).to_string();
            return Some((key, val));
        }
    }
    None
}

/// parse ErrorResponse payload and return the 'M' field (human message) if present
fn parse_error_response(payload: &[u8]) -> Option<String> {
    let mut i = 0usize;
    while i < payload.len() {
        let field_type = payload[i];
        i += 1;
        if field_type == 0 { break; } // terminator
        if let Some(pos) = payload[i..].iter().position(|&b| b == 0) {
            let val = String::from_utf8_lossy(&payload[i..i+pos]).to_string();
            if field_type == b'M' {
                return Some(val);
            }
            i += pos + 1;
        } else {
            break;
        }
    }
    None
}
