use anyhow::Result;
use clap::{ArgAction, Parser};
use cidr::Ipv4Cidr;
use futures::stream::{FuturesUnordered, StreamExt};
use futures::Future;
use serde::Serialize;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio::sync::Semaphore;
use std::sync::Arc;
use indicatif::{ProgressBar, ProgressStyle};
use colored::*;
use trust_dns_proto::op::Message;
use trust_dns_proto::serialize::binary::BinDecodable;
use chrono::{NaiveDateTime, Utc};


#[derive(Parser, Debug)]
#[command(name = "rustlite-scan", about = "Fast async port scanner (TCP/UDP) in Rust")]
struct Cli {
    /// Target host/IP or CIDR (e.g., 192.168.1.0/24)
    #[arg(short, long)]
    target: String,

    /// Ports to scan, e.g., 1-1024 or comma-separated (80,443,8080)
    #[arg(short, long, default_value = "1-1024")]
    ports: String,

    /// UDP probe in addition to TCP
    #[arg(long, action = ArgAction::SetTrue)]
    udp: bool,

    /// Max concurrent scans
    #[arg(short = 'c', long, default_value_t = 1024)]
    concurrency: usize,

    /// Connect timeout in milliseconds
    #[arg(long, default_value_t = 800)]
    connect_timeout_ms: u64,

    /// Per-UDP probe timeout in milliseconds
    #[arg(long, default_value_t = 1200)]
    udp_timeout_ms: u64,

    /// JSON output
    #[arg(long, action = ArgAction::SetTrue)]
    json: bool,
}

#[derive(Debug, Serialize, Clone)]
struct PortResult {
    port: u16,
    protocol: &'static str, // "tcp" or "udp"
    state: &'static str,    // "open", "closed", "filtered", "unknown"
    banner: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct HostResult {
    host: String,
    ip: String,
    results: Vec<PortResult>,
}

fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    // Accept "1-1024" or "22,80,443"
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if let Some((a, b)) = part.split_once('-') {
            let start: u16 = a.parse()?;
            let end: u16 = b.parse()?;
            for p in start.min(end)..=start.max(end) {
                ports.push(p);
            }
        } else {
            ports.push(part.parse()?);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn expand_targets(target: &str) -> Result<Vec<String>> {
    // If CIDR, expand; otherwise resolve to A/AAAA records
    if target.contains('/') {
        let cidr: Ipv4Cidr = target.parse()?;
        Ok(cidr.iter().map(|ip| ip.to_string()).collect())
    } else {
        // Use &target to avoid the unstable str::as_str confusion
        let addrs = (target, 0).to_socket_addrs()?;
        let mut ips = addrs
            .filter_map(|sa| match sa {
                SocketAddr::V4(v4) => Some(v4.ip().to_string()),
                SocketAddr::V6(v6) => Some(v6.ip().to_string()),
            })
            .collect::<Vec<_>>();

        ips.sort();
        ips.dedup();

        if ips.is_empty() {
            // Fallback: treat as literal IP or hostname string
            Ok(vec![target.to_string()])
        } else {
            Ok(ips)
        }
    }
}

async fn tcp_probe(ip: String, port: u16, timeout_ms: u64) -> PortResult {
    let addr = format!("{}:{}", ip, port);
    let fut = TcpStream::connect(addr);
    match timeout(Duration::from_millis(timeout_ms), fut).await {
        Ok(Ok(mut stream)) => {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut banner = None;

            match port {
                80 | 443 | 8080 => {
                    // HTTP banner grab
                    let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
                    let mut buf = vec![0u8; 512];
                    if let Ok(n) = timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
                        if let Ok(n) = n {
                            banner = Some(String::from_utf8_lossy(&buf[..n]).to_string());
                        }
                    }
                }
                22 => {
                    // SSH banner grab (server sends immediately)
                    let mut buf = vec![0u8; 128];
                    if let Ok(n) = timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
                        if let Ok(n) = n {
                            banner = Some(String::from_utf8_lossy(&buf[..n]).to_string());
                        }
                    }
                }
                25 => {
                    // SMTP banner grab (server sends greeting)
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


async fn udp_probe(ip: String, port: u16, timeout_ms: u64) -> PortResult {
    let local = "0.0.0.0:0";
    let addr = format!("{}:{}", ip, port);

    match UdpSocket::bind(local).await {
        Ok(sock) => {
            let _ = sock.connect(&addr).await;

            // Payload selection
            let payload: Vec<u8> = match port {
                53 => { /* DNS query as before */ vec![ /* ... */ ] }
                123 => {
                    // NTP request
                    let mut pkt = vec![0u8; 48];
                    pkt[0] = 0x1B; // LI=0, VN=3, Mode=3 (client)
                    pkt
                }
                _ => vec![],
            };

            let _ = sock.send(&payload).await;

            let mut buf = [0u8; 512];
            let res = timeout(Duration::from_millis(timeout_ms), sock.recv(&mut buf)).await;

            match res {
                Ok(Ok(n)) => {
                    let banner = if port == 123 && n >= 48 {
                        // NTP timestamp starts at byte 40 (Transmit Timestamp)
                        let secs = u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]) as u64;
                        let frac = u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]) as u64;

                        // NTP epoch starts 1900-01-01, Unix epoch 1970-01-01
                        let ntp_to_unix = 2_208_988_800u64;
                        let unix_secs = secs.saturating_sub(ntp_to_unix);

                        let naive = NaiveDateTime::from_timestamp_opt(unix_secs as i64, 0);
                        if let Some(dt) = naive {
                            Some(format!("NTP time: {}", dt.format("%Y-%m-%d %H:%M:%S UTC")))
                        } else {
                            Some("NTP response (invalid timestamp)".to_string())
                        }
                    } else if port == 53 {
                        Some(format!("{} bytes DNS response", n)) // keep DNS parsing from earlier
                    } else {
                        Some(format!("{} bytes response", n))
                    };

                    PortResult { port, protocol: "udp", state: "open", banner }
                }
                Ok(Err(_)) => PortResult { port, protocol: "udp", state: "unknown", banner: None },
                Err(_) => PortResult { port, protocol: "udp", state: "open|filtered", banner: None },
            }
        }
        Err(_) => PortResult { port, protocol: "udp", state: "unknown", banner: None },
    }
}


// Unified future type so FuturesUnordered can hold both tcp_probe and udp_probe futures
type ScanFuture = Pin<Box<dyn Future<Output = PortResult> + Send>>;

async fn scan_host(
    ip: String,
    ports: &[u16],
    udp: bool,
    conc: usize,
    tcp_to_ms: u64,
    udp_to_ms: u64,
) -> HostResult {
    let semaphore = Arc::new(Semaphore::new(conc));
    let mut tasks = FuturesUnordered::<ScanFuture>::new();

    // progress bar setup
    let total = ports.len() as u64 * if udp { 2 } else { 1 };
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    for &p in ports {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let ip_owned = ip.to_string();
        let pb_clone = pb.clone();
        tasks.push(Box::pin(async move {
            let res = tcp_probe(ip_owned, p, tcp_to_ms).await;
            pb_clone.inc(1);
            drop(permit);
            res
        }));

        if udp {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let ip_owned = ip.to_string();
            let pb_clone = pb.clone();
            tasks.push(Box::pin(async move {
                let res = udp_probe(ip_owned, p, udp_to_ms).await;
                pb_clone.inc(1);
                drop(permit);
                res
            }));
        }
    }

    let mut results = Vec::new();
    while let Some(r) = tasks.next().await {
        results.push(r);
    }

    pb.finish_with_message("Scan complete");

    HostResult { host: ip.to_string(), ip: ip.to_string(), results }
}


#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let ports = parse_ports(&cli.ports)?;
    let targets = expand_targets(&cli.target)?;

    let mut all = Vec::new();
    for ip in targets {
        let host_result = scan_host(
            ip,
            &ports,
            cli.udp,
            cli.concurrency,
            cli.connect_timeout_ms,
            cli.udp_timeout_ms,
        )
        .await;
        all.push(host_result.clone());

        if cli.json {
            println!("{}", serde_json::to_string_pretty(&host_result)?);
        } else {
            println!("Host: {}", host_result.ip);
            for r in host_result
                .results
                .iter()
                .filter(|r| r.state == "open" || r.state == "open|filtered")
            {
                let banner = r.banner.as_deref().unwrap_or("");
                if banner.is_empty() {
                    println!("  {} {:>5}  {}", r.protocol, r.port, r.state);
                } else {
                    println!(
                        "  {} {:>5}  {}  banner: {}",
                        r.protocol,
                        r.port,
                        r.state,
                        banner.replace('\n', "\\n")
                    );
                }
            }
        }
    }

    if cli.json {
        // Optional: aggregate output across hosts
        eprintln!("{}", serde_json::to_string_pretty(&all)?);
    }

    Ok(())
}
