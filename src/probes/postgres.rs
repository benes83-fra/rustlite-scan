// probes/postgres.rs
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use bytes::{Buf, BytesMut};
use crate::probes::helper::push_line;
use crate::service::ServiceFingerprint;
use super::Probe;

pub struct PostgresProbe;

#[async_trait::async_trait]
impl Probe for PostgresProbe {
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

fn build_startup_message(user: &str) -> Vec<u8> {
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

async fn read_server_messages(stream: &mut TcpStream, to: Duration) -> Result<PgInfo, String> {
    let mut buf = BytesMut::with_capacity(4096);
    let mut info = PgInfo { server_version: None, auth_required: false, protocol_version: None };

    // read loop: parse messages until we see server_version or an auth request
    loop {
        // read header (1 byte type + 4 bytes length) or, for initial messages, server may send an Error/Authentication without type?
        let mut header = [0u8; 5];
        match timeout(to, stream.read_exact(&mut header)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("read error: {}", e)),
            Err(_) => return Err("read timeout".into()),
        }

        let typ = header[0] as char;
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if len < 4 {
            return Err("invalid message length".into());
        }
        let payload_len = len - 4;
        buf.resize(payload_len, 0);
        match timeout(to, stream.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("read payload error: {}", e)),
            Err(_) => return Err("payload read timeout".into()),
        }

        match typ {
            'R' => {
                // Authentication request: first 4 bytes = auth code
                if payload_len >= 4 {
                    let code = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    // 0 = AuthenticationOk, others require auth
                    if code == 0 {
                        info.auth_required = false;
                    } else {
                        info.auth_required = true;
                        // continue reading: server may still send ParameterStatus after auth ok, but usually not
                    }
                } else {
                    info.auth_required = true;
                }
            }
            'S' => {
                // ParameterStatus: key\0value\0
                if let Some((k, v)) = parse_cstring_pair(&buf) {
                    if k == "server_version" {
                        info.server_version = Some(v);
                    }
                }
            }
            'K' => {
                // BackendKeyData: pid(4) + secret(4) - ignore
            }
            'E' => {
                // ErrorResponse: may contain fields; sometimes includes server info in 'M' message
                // parse for 'M' message text or 'S' severity; we will not extract version here
            }
            'Z' => {
                // ReadyForQuery - end of startup
                break;
            }
            _ => {
                // ignore other message types
            }
        }

        // stop early if we found server_version
        if info.server_version.is_some() {
            break;
        }
    }

    Ok(info)
}

fn parse_cstring_pair(buf: &[u8]) -> Option<(String, String)> {
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
