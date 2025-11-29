use crate::types::PortResult;
use tokio::net::TcpStream;
use tokio::time::timeout;
use std::net::ToSocketAddrs;
use std::time::Duration;
use std::net::{IpAddr, SocketAddr};

pub async fn tcp_probe(ip: &str, port: u16, timeout_ms: u64) -> PortResult {
    // Parse ip to IpAddr and build a SocketAddr so IPv6 is handled correctly
    let socket = match ip.parse::<IpAddr>() {
        Ok(ipaddr) => SocketAddr::new(ipaddr, port),
        Err(_) => {
            // Fallback: try to resolve via ToSocketAddrs by formatting as host:port
            // This keeps previous behavior for hostnames
            let addr_str = format!("{}:{}", ip, port);
            match addr_str.to_socket_addrs() {
                Ok(mut iter) => match iter.next() {
                    Some(sa) => sa,
                    None => {
                        return PortResult { port, protocol: "tcp", state: "unknown", banner: None };
                    }
                },
                Err(_) => {
                    return PortResult { port, protocol: "tcp", state: "unknown", banner: None };
                }
            }
        }
    };

    let fut = TcpStream::connect(socket);
    match timeout(Duration::from_millis(timeout_ms), fut).await {
        Ok(Ok(mut stream)) => {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut banner = None;

            match port {
                80 | 443 | 8080 => {
                    let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
                    let mut buf = vec![0u8; 512];
                    if let Ok(n) = timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
                        if let Ok(n) = n {
                            banner = Some(String::from_utf8_lossy(&buf[..n]).to_string());
                        }
                    }
                }
                22 => {
                    let mut buf = vec![0u8; 128];
                    if let Ok(n) = timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
                        if let Ok(n) = n {
                            banner = Some(String::from_utf8_lossy(&buf[..n]).to_string());
                        }
                    }
                }
                25 => {
                    let mut buf = vec![0u8; 256];
                    if let Ok(n) = timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
                        if let Ok(n) = n {
                            banner = Some(String::from_utf8_lossy(&buf[..n]).to_string());
                        }
                    }
                }
                _ => {}
            }

            PortResult { port, protocol: "tcp", state: "open", banner }
        }
        Ok(Err(_)) => PortResult { port, protocol: "tcp", state: "closed", banner: None },
        Err(_) => PortResult { port, protocol: "tcp", state: "filtered", banner: None },
    }
}
