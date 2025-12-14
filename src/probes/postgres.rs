// probes/postgres.rs
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use bytes::{Buf, BytesMut};
use std::fmt::Write as FmtWrite;
use crate::probes::ProbeContext;
use crate::probes::helper::push_line;
use crate::service::ServiceFingerprint;
use super::Probe;

pub struct PostgresProbe;

#[async_trait::async_trait]
impl Probe for PostgresProbe {
    async fn probe_with_ctx (&self, ip : &str , port :u16, ctx :ProbeContext) -> Option <ServiceFingerprint>{
        
        let timeout_ms = ctx.get("timeout_ms").and_then(|s| s.parse::<u64>().ok()).unwrap_or(2000);
        self.probe(ip, port, timeout_ms).await
    }
    async fn probe(&self, ip: &str, _port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let mut evidence = String::new();
        let addr = format!("{}:5432", ip);
        let to = Duration::from_millis(timeout_ms);

        match timeout(to, TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                // send StartupMessage
                let startup = build_startup_message("rustlite_probe");
                if let Err(e) = timeout(to, stream.write_all(&startup)).await {
                    push_line(&mut evidence, "postgres", &format!("error: write timeout {}", e));
                    return Some(ServiceFingerprint::from_banner(ip, 5432, "postgres", evidence));
                }
                eprintln! ("We send the message and got {:?}",startup);
                // read responses until we find server_version or auth request
                match read_server_messages(&mut stream, to).await {
                    Ok(info) => {
                        if let Some(ver) = info.server_version {
                            push_line(&mut evidence, "postgres_version", &ver);
                        } else {
                            push_line(&mut evidence, "postgres_version", "unknown");
                        }
                        push_line(&mut evidence, "postgres_auth_required", &format!("{}", info.auth_required));
                        if let Some(proto) = info.protocol_version {
                            push_line(&mut evidence, "postgres_protocol_version", &format!("{}", proto));
                        }
                    }
                    Err(e) => {
                        eprintln! ("The following went wrong : {:?}",e);
                        push_line(&mut evidence, "postgres", &format!("error: {}", e));
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

        Some(ServiceFingerprint::from_banner(ip, 5432, "postgres", evidence))
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

pub fn build_startup_message(user: &str) -> Vec<u8> {
    // StartupMessage: length(4) + protocol(4) + key\0value\0 ... \0
    // protocol 196608 (3.0) is 0x00030000
    let mut body = Vec::new();
    body.extend_from_slice(&0x00030000u32.to_be_bytes()); // protocol
    body.extend_from_slice(b"user\0");
    body.extend_from_slice(user.as_bytes());
    body.push(0);
    body.push(0); // terminator

    let len = (4 + body.len()) as u32;
    let mut msg = Vec::with_capacity(len as usize);
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(&body);
    msg
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};
fn hex_dump(buf: &[u8]) -> String {
    let mut s = String::new();
    for b in buf { let _ = write!(&mut s, "{:02x}", b); }
    s
}


async fn read_server_messages(stream: &mut TcpStream, to: Duration) -> Result<PgInfo, String> {
    let mut info = PgInfo { server_version: None, auth_required: false, protocol_version: None };
    let mut partial = Vec::new();

    loop {
        // Try to read the first byte (message type or SSL single-byte reply)
        let mut first = [0u8; 1];
        match timeout(to, stream.read_exact(&mut first)).await {
            Ok(Ok(_)) => { partial.push(first[0]); }
            Ok(Err(e)) => {
                // if we got nothing at all, return a helpful error with any partial bytes
                let hex = hex_dump(&partial);
                return Err(format!("read error: {} (partial={})", e, hex));
            }
            Err(_) => {
                let hex = hex_dump(&partial);
                return Err(format!("read timeout (partial={})", hex));
            }
        }

        // SSL negotiation reply is a single byte 'S' or 'N' (0x53/0x4e)
        if first[0] == b'S' || first[0] == b'N' {
            // server expects SSL negotiation; we didn't request SSL, so treat as auth required/unsupported
            return Err(format!("server requested SSL (reply={}), partial={}", first[0] as char, hex_dump(&partial)));
        }

        // Otherwise read the 4-byte length
        let mut lenb = [0u8; 4];
        match timeout(to, stream.read_exact(&mut lenb)).await {
            Ok(Ok(_)) => { partial.extend_from_slice(&lenb); }
            Ok(Err(e)) => {
                return Err(format!("read length error: {} (partial={})", e, hex_dump(&partial)));
            }
            Err(_) => {
                return Err(format!("read length timeout (partial={})", hex_dump(&partial)));
            }
        }

        let typ = first[0] as char;
        let len = u32::from_be_bytes(lenb) as usize;
        if len < 4 {
            return Err(format!("invalid message length {} (partial={})", len, hex_dump(&partial)));
        }
        let payload_len = len - 4;
        let mut payload = vec![0u8; payload_len];
        match timeout(to, stream.read_exact(&mut payload)).await {
            Ok(Ok(_)) => { /* good */ }
            Ok(Err(e)) => {
                partial.extend_from_slice(&payload);
                return Err(format!("read payload error: {} (partial={})", e, hex_dump(&partial)));
            }
            Err(_) => {
                partial.extend_from_slice(&payload);
                return Err(format!("payload read timeout (partial={})", hex_dump(&partial)));
            }
        }

        // parse as before, using payload
        match typ {
            'R' => { /* same handling */ }
            'S' => { /* ParameterStatus parsing using payload */ }
            'Z' => break,
            'E' => {
                // ErrorResponse: series of fields: <field type byte><cstring> ... 0x00 terminator
                // We look for the 'M' field (human-readable message)
                let mut i = 0;
                while i < payload.len() {
                    let field_type = payload[i];
                    i += 1;
                    if field_type == 0 { break; } // terminator
                    if let Some(pos) = payload[i..].iter().position(|&b| b == 0) {
                        let val = String::from_utf8_lossy(&payload[i..i+pos]).to_string();
                        if field_type == b'M' {
                            // human-readable message
                            info.server_version = None;
                            // store the error message somewhere or return it
                            return Err(format!("server error: {}", val));
                        }
                        i += pos + 1;
                    } else {
                        break;
                    }
                }
            }
            _ => {}
        }

        if info.server_version.is_some() { break; }
    }

    Ok(info)
}

pub fn parse_cstring_pair(buf: &[u8]) -> Option<(String, String)> {
    // find first NUL
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
