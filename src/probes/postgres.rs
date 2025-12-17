// src/probes/postgres.rs (or wherever your Postgres probe lives)
use crate::probes::helper::push_line;
use crate::probes::ProbeContext;
use crate::service::ServiceFingerprint;
use super::Probe;
use tokio::time::{timeout, Duration};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

use crate::probes::helper;
pub struct PostgresProbe;

const DEBUG:bool=true;

enum EitherStream {
    Plain(tokio::net::TcpStream),
    Tls(tokio_openssl::SslStream<tokio::net::TcpStream>),
}


/// Connect, send SSLRequest and upgrade to TLS if server replies 'S'.
/// Returns either a boxed plain TcpStream (if server replies 'N') or a boxed SslStream (if 'S').
async fn connect_and_maybe_upgrade(
    ip: &str,
    port: u16,
    timeout_ms: u64,
) -> Result<EitherStream, String> {
    // Use your helper to connect with timeout
    let tcp = helper::connect_with_timeout(ip, port, timeout_ms)
        .await
        .ok_or_else(|| "connect timeout".to_string())?;

    // Build SSLRequest: length=8, code=80877103
    let mut ssl_req = Vec::with_capacity(8);
    ssl_req.extend_from_slice(&8u32.to_be_bytes());
    ssl_req.extend_from_slice(&80877103u32.to_be_bytes());

    // send SSLRequest and read single byte reply
    if timeout(Duration::from_millis(500), tcp.writable()).await.is_err() {
        return Err("ssl request write timeout".into());
    }
    let mut tcp = tcp;
    timeout(Duration::from_millis(500), tcp.write_all(&ssl_req))
        .await
        .map_err(|_| "ssl request write timeout".to_string())?
        .map_err(|e| format!("ssl request write error: {}", e))?;

    let mut reply = [0u8; 1];
    timeout(Duration::from_millis(500), tcp.read_exact(&mut reply))
        .await
        .map_err(|_| "ssl reply read timeout".to_string())?
        .map_err(|e| format!("ssl reply read error: {}", e))?;
    if DEBUG {eprintln!("{} will decide whether we go TLS.",reply[0]);}
    match reply[0] {
        b'S' => {
            // server accepts TLS: call your helper upgrade_to_tls which returns SslStream<TcpStream>
            if DEBUG {eprintln!("We definitely are SSLing");}
            match helper::upgrade_to_tls(tcp, ip).await {
                Ok(tls_stream) => Ok(EitherStream::Tls(tls_stream)),
                Err(_) => Err("tls upgrade failed".into()),
            }
        }
        b'N' => Ok(EitherStream::Plain(tcp)),
        other => Err(format!("unexpected ssl reply byte: 0x{:02x}", other)),
    }
}

/// Small enum to hold either stream type


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

            
            match connect_and_maybe_upgrade(ip, 5432, timeout_ms).await {
                Ok(EitherStream::Tls(mut tls_stream)) => {
                // send startup
                    if let Err(e) = timeout(timeout_dur, tls_stream.write_all(&startup)).await {
                        push_line(&mut evidence, "postgres", &format!("write_error: {}", e));
                    } else {
                        match read_server_messages_generic(&mut tls_stream, timeout_dur).await {
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
                                if let Some(fp) = crate::probes::tls::fingerprint_tls(ip, 5432, "postgres", String::new(), tls_stream).await {
                            
                                    if let Some(ev) = fp.evidence {
                                        if !evidence.is_empty() { evidence.push('\n'); }
                                        evidence.push_str(&ev);
                                    }
                                }
                            }
                                
                            Err(e) => {
                                // include which user/db we tried for DEBUGging (but avoid leaking secrets)
                                if let Some(fp) = crate::probes::tls::fingerprint_tls(ip, 5432, "postgres",String::new(), tls_stream).await {
                                    
                                    if let Some (ev) =fp.evidence{
                                        if !evidence.is_empty() {evidence.push('\n');}
                                        evidence.push_str(&ev);
                                    }
                                    
                                   
                                }
                                push_line(&mut evidence, "postgres_error", &format!("user={} db={} err={}", user, db, e));
                                // continue to next combo
                            }
                        }
                      
                    // read server messages and interpret
                    
                    }
                }
                Ok(EitherStream::Plain(mut tcp)) => {
                    
                    if let Err(e) = timeout(timeout_dur, tcp.write_all(&startup)).await {
                        push_line(&mut evidence, "postgres", &format!("write_error: {}", e));
                        continue;
                    }
                    if DEBUG {eprintln!("We are in normal TCP");}
                    // read server messages and interpret
                    match read_server_messages_generic(&mut tcp, timeout_dur).await {
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
                            // include which user/db we tried for DEBUGging (but avoid leaking secrets)
                            push_line(&mut evidence, "postgres_error", &format!("user={} db={} err={}", user, db, e));
                            // continue to next combo
                        }
                }
                  
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




async fn read_server_messages_generic<S>(stream: &mut S, to: Duration) -> Result<PgInfo, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut info = PgInfo { server_version: None, auth_required: false, protocol_version: None };
    let mut buf = BytesMut::with_capacity(4096);

    loop {
        // read first byte (type) or single-byte SSL reply
        // read first byte (type)
       // read first byte (type)
        let mut first = [0u8; 1];
        match timeout(to, stream.read_exact(&mut first)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("read error: {}", e)),
            Err(_) => return Err("read timeout".into()),
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

pub async fn probe_postgres_minimal_no_creds(
    ip: &str,
    port: u16,
    timeout_ms: u64,
) -> Option<ServiceFingerprint> {
    let mut evidence = String::new();
    let timeout_dur = Duration::from_millis(timeout_ms);

    // 1) Connect (with helper)
    let mut tcp = match helper::connect_with_timeout(ip, port, timeout_ms).await {
        Some(s) => s,
        None => {
            push_line(&mut evidence, "postgres", "connect_timeout");
            return Some(ServiceFingerprint::from_banner(ip, port, "postgres", evidence));
        }
    };

    // 2) Send SSLRequest and read single-byte reply
    // SSLRequest: length=8, code=80877103
    let mut ssl_req = Vec::with_capacity(8);
    ssl_req.extend_from_slice(&8u32.to_be_bytes());
    ssl_req.extend_from_slice(&80877103u32.to_be_bytes());

    if timeout(Duration::from_millis(500), tcp.write_all(&ssl_req)).await.is_err() {
        push_line(&mut evidence, "postgres", "ssl_request_write_timeout");
        return Some(ServiceFingerprint::from_banner(ip, port, "postgres", evidence));
    }

    let mut reply = [0u8; 1];
    if timeout(Duration::from_millis(500), tcp.read_exact(&mut reply)).await.is_err() {
        push_line(&mut evidence, "postgres", "ssl_reply_read_timeout");
        return Some(ServiceFingerprint::from_banner(ip, port, "postgres", evidence));
    }

  

    let mut stream_kind = match reply[0] {
        b'S' => {
            // try to upgrade to TLS using your helper
            match helper::upgrade_to_tls(tcp, ip).await {
                Ok(tls_stream) => EitherStream::Tls(tls_stream),
                Err(_) => {
                    push_line(&mut evidence, "postgres", "tls_upgrade_failed");
                    return Some(ServiceFingerprint::from_banner(ip, port, "postgres", evidence));
                }
            }
        }
        b'N' => EitherStream::Plain(tcp),
        other => {
            push_line(&mut evidence, "postgres", &format!("unexpected_ssl_reply: 0x{:02x}", other));
            return Some(ServiceFingerprint::from_banner(ip, port, "postgres", evidence));
        }
    };

    // 4) Build minimal StartupMessage (protocol 3.0). No user/db by default.
    let startup = build_startup_message_minimal();

    // 5) Send StartupMessage and parse server messages
    // We'll parse S (ParameterStatus), R (Authentication), E (ErrorResponse), Z (ReadyForQuery)
    // and stop once we have server_version and auth info or after ReadyForQuery.
    let parse_result = match &mut stream_kind {
        EitherStream::Plain(ref mut s) => {
            if timeout(timeout_dur, s.write_all(&startup)).await.is_err() {
                push_line(&mut evidence, "postgres", "startup_write_timeout_plain");
                return Some(ServiceFingerprint::from_banner(ip, port, "postgres", evidence));
            }
            read_server_messages_generic(s, timeout_dur).await
        }
        EitherStream::Tls(ref mut s) => {
            if timeout(timeout_dur, s.write_all(&startup)).await.is_err() {
                push_line(&mut evidence, "postgres", "startup_write_timeout_tls");
                // still try to fingerprint certs below
                read_server_messages_generic(s, timeout_dur).await
            } else {
                read_server_messages_generic(s, timeout_dur).await
            }
        }
    };

    // parse_result contains PgInfo or error
    match parse_result {
        Ok(info) => {
            if let Some(ver) = info.server_version {
                push_line(&mut evidence, "postgres_version", &ver);
            } else {
                push_line(&mut evidence, "postgres_version", "unknown");
            }
            push_line(&mut evidence, "postgres_auth_required", &format!("{}", info.auth_required));
            if let Some(code) = info.protocol_version {
                let mapped = map_auth_code(code);
                push_line(&mut evidence, "postgres_auth_method", &format!("{} ({})", mapped, code));
            }
        }
        Err(e) => {
            push_line(&mut evidence, "postgres_error", &e);
        }
    }

    // 6) If TLS was used, extract cert evidence by consuming the SslStream via your helper
    if let EitherStream::Tls(tls_stream) = stream_kind {
        // fingerprint_tls consumes the SslStream and returns ServiceFingerprint with evidence
        if let Some(fp) = crate::probes::tls::fingerprint_tls(ip, port, "postgres", evidence.clone(), tls_stream).await {
            if let Some(ev) = fp.evidence {
                // merge TLS evidence with existing evidence
                let mut merged = evidence;
                if !merged.is_empty() { merged.push('\n'); }
                merged.push_str(&ev);
                return Some(ServiceFingerprint::from_banner(ip, port, "postgres", merged));
            }
        }
    }

    Some(ServiceFingerprint::from_banner(ip, port, "postgres", evidence))
}

/// Build a minimal StartupMessage (protocol 3.0) with no user/db fields.
/// Format: length (4) + protocol (4) + sequence of key\0value\0 pairs + final 0
fn build_startup_message_minimal() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x00030000u32.to_be_bytes()); // protocol 3.0
    // Optionally add application_name or other harmless params if desired:
    // body.extend_from_slice(b"application_name\0rustlite_scan\0");
    body.push(0); // terminator for parameters (no key/value pairs)
    let len = (4 + body.len()) as u32;
    let mut msg = Vec::with_capacity(len as usize);
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(&body);
    msg
}

/// Map common Authentication codes to readable names
fn map_auth_code(code: u32) -> &'static str {
    match code {
        0 => "AuthenticationOk",
        2 => "AuthenticationKerberosV5",
        3 => "AuthenticationCleartextPassword",
        5 => "AuthenticationMD5Password",
        6 => "AuthenticationSCMCredential",
        7 => "AuthenticationGSS",
        8 => "AuthenticationSSPI",
        9 => "AuthenticationGSSContinue",
        10 => "AuthenticationSASL",
        11 => "AuthenticationSASLContinue",
        12 => "AuthenticationSASLFinal",
        _ => "AuthenticationUnknown",
    }
}