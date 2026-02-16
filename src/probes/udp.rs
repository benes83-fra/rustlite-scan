use crate::types::PortResult;
use crate::utils::RateLimiter;
use chrono::DateTime;
use rand::Rng;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout, Duration};
use trust_dns_proto::op::Message;
use trust_dns_proto::serialize::binary::BinDecodable;

#[derive(Debug, Clone, Default)]
pub struct UdpProbeStats {
    pub attempts: u64,
    pub retries: u64,
    pub timeouts: u64,
    pub successes: u64,
    pub packets_sent: u64,
    pub packets_received: u64,

    // limiter metadata for diagnostics
    pub host_limiter_pps: Option<u64>,
    pub host_limiter_burst: Option<u64>,
    pub global_limiter_pps: Option<u64>,
    pub global_limiter_burst: Option<u64>,
}

pub async fn udp_probe(
    ip: &str,
    port: u16,
    timeout_ms: u64,
    retries: u8,
    backoff_ms: u64,
    global_limiter: Option<Arc<RateLimiter>>,
    host_limiter: Option<Arc<RateLimiter>>,
) -> (PortResult, UdpProbeStats) {
    let mut stats = UdpProbeStats::default();
    let local = "0.0.0.0:0";

    // Populate limiter metadata (if present)
    if let Some(ref hl) = host_limiter {
        stats.host_limiter_pps = Some(hl.pps());
        stats.host_limiter_burst = Some(hl.burst());
    }
    if let Some(ref gl) = global_limiter {
        stats.global_limiter_pps = Some(gl.pps());
        stats.global_limiter_burst = Some(gl.burst());
    }

    let payload: Vec<u8> = match port {
        53 => vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ],
        123 => {
            let mut pkt = vec![0u8; 48];
            pkt[0] = 0x1B;
            pkt
        }
        _ => vec![],
    };

    let socket_addr: SocketAddr = match ip.parse::<IpAddr>() {
        Ok(ipaddr) => SocketAddr::new(ipaddr, port),
        Err(_) => {
            let addr_str = format!("{}:{}", ip, port);
            match addr_str.to_socket_addrs() {
                Ok(mut iter) => match iter.next() {
                    Some(sa) => sa,
                    None => {
                        return (
                            PortResult {
                                port,
                                protocol: "udp",
                                state: "unknown",
                                banner: None,
                                ttl: None,
                                window_size: None,
                                mss: None,
                                df: None,
                                ts: None,
                                ws: None,
                                sackok: None,
                                ecn: None,
                            },
                            stats,
                        )
                    }
                },
                Err(_) => {
                    return (
                        PortResult {
                            port,
                            protocol: "udp",
                            state: "unknown",
                            banner: None,
                            ttl: None,
                            window_size: None,
                            mss: None,
                            df: None,
                            ts: None,
                            ws: None,
                            sackok: None,
                            ecn: None,
                        },
                        stats,
                    )
                }
            }
        }
    };

    match UdpSocket::bind(local).await {
        Ok(sock) => {
            let _ = sock.connect(socket_addr).await;

            // initial send (rate-limited)
            stats.attempts += 1;

            // small randomized jitter to avoid synchronized bursts
            let jitter = rand::thread_rng().gen_range(0..20);
            if jitter > 0 {
                tokio::time::sleep(Duration::from_millis(jitter)).await;
            }

            // Acquire host limiter first (fairness), then global limiter
            if let Some(hl) = &host_limiter {
                hl.acquire().await;
            }
            if let Some(gl) = &global_limiter {
                gl.acquire().await;
            }

            let _ = sock.send(&payload).await;
            stats.packets_sent += 1;

            let mut buf = [0u8; 2048];
            let attempts = 1usize + (retries as usize);

            for attempt in 0..attempts {
                let attempt_timeout = timeout_ms.saturating_mul(1 + attempt as u64);
                let recv_fut = sock.recv(&mut buf);
                let to = timeout(Duration::from_millis(attempt_timeout), recv_fut);

                match to.await {
                    Ok(Ok(n)) => {
                        stats.successes += 1;
                        stats.packets_received += 1;
                        if port == 53 {
                            if let Ok(msg) = Message::from_bytes(&buf[..n]) {
                                let answers: Vec<String> =
                                    msg.answers().iter().map(|rr| format!("{}", rr)).collect();
                                let banner = if answers.is_empty() {
                                    Some(format!("DNS response {} bytes", n))
                                } else {
                                    Some(answers.join(", "))
                                };
                                return (
                                    PortResult {
                                        port,
                                        protocol: "udp",
                                        state: "open",
                                        banner,
                                        ttl: None,
                                        window_size: None,
                                        mss: None,
                                        df: None,
                                        ts: None,
                                        ws: None,
                                        sackok: None,
                                        ecn: None,
                                    },
                                    stats,
                                );
                            } else {
                                return (
                                    PortResult {
                                        port,
                                        protocol: "udp",
                                        state: "open",
                                        banner: Some(format!("{} bytes DNS (unparsed)", n)),
                                        ttl: None,
                                        window_size: None,
                                        mss: None,
                                        df: None,
                                        ts: None,
                                        ws: None,
                                        sackok: None,
                                        ecn: None,
                                    },
                                    stats,
                                );
                            }
                        } else if port == 123 && n >= 48 {
                            let secs =
                                u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]) as u64;
                            let ntp_to_unix = 2_208_988_800u64;
                            let unix_secs = secs.saturating_sub(ntp_to_unix);
                            let naive = DateTime::from_timestamp(unix_secs as i64, 0);
                            let banner = naive
                                .map(|dt| {
                                    format!("NTP time: {}", dt.format("%Y-%m-%d %H:%M:%S UTC"))
                                })
                                .or(Some(format!("NTP response {} bytes", n)));
                            return (
                                PortResult {
                                    port,
                                    protocol: "udp",
                                    state: "open",
                                    banner,
                                    ttl: None,
                                    window_size: None,
                                    mss: None,
                                    df: None,
                                    ts: None,
                                    ws: None,
                                    sackok: None,
                                    ecn: None,
                                },
                                stats,
                            );
                        } else {
                            return (
                                PortResult {
                                    port,
                                    protocol: "udp",
                                    state: "open",
                                    banner: Some(format!("{} bytes response", n)),
                                    ttl: None,
                                    window_size: None,
                                    mss: None,
                                    df: None,
                                    ts: None,
                                    ws: None,
                                    sackok: None,
                                    ecn: None,
                                },
                                stats,
                            );
                        }
                    }
                    Ok(Err(_)) => {
                        return (
                            PortResult {
                                port,
                                protocol: "udp",
                                state: "unknown",
                                banner: None,
                                ttl: None,
                                window_size: None,
                                mss: None,
                                df: None,
                                ts: None,
                                ws: None,
                                sackok: None,
                                ecn: None,
                            },
                            stats,
                        );
                    }
                    Err(_) => {
                        stats.timeouts += 1;
                        if attempt + 1 < attempts {
                            stats.retries += 1;
                            stats.attempts += 1;

                            let exp = 1u64 << attempt;
                            let base = backoff_ms.saturating_mul(exp);
                            let jitter = rand::thread_rng().gen_range(0..(base.max(1)));
                            let wait = base.saturating_add(jitter);
                            sleep(Duration::from_millis(wait)).await;

                            // resend (rate-limited) with small jitter
                            let jitter2 = rand::thread_rng().gen_range(0..10);
                            if jitter2 > 0 {
                                tokio::time::sleep(Duration::from_millis(jitter2)).await;
                            }

                            if let Some(hl) = &host_limiter {
                                hl.acquire().await;
                            }
                            if let Some(gl) = &global_limiter {
                                gl.acquire().await;
                            }
                            let _ = sock.send(&payload).await;
                            stats.packets_sent += 1;
                            continue;
                        } else {
                            return (
                                PortResult {
                                    port,
                                    protocol: "udp",
                                    state: "open|filtered",
                                    banner: None,
                                    ttl: None,
                                    window_size: None,
                                    mss: None,
                                    df: None,
                                    ts: None,
                                    ws: None,
                                    sackok: None,
                                    ecn: None,
                                },
                                stats,
                            );
                        }
                    }
                }
            }

            (
                PortResult {
                    port,
                    protocol: "udp",
                    state: "unknown",
                    banner: None,
                    ttl: None,
                    window_size: None,
                    mss: None,
                    df: None,
                    ts: None,
                    ws: None,
                    sackok: None,
                    ecn: None,
                },
                stats,
            )
        }
        Err(_) => (
            PortResult {
                port,
                protocol: "udp",
                state: "unknown",
                banner: None,
                ttl: None,
                window_size: None,
                mss: None,
                df: None,
                ts: None,
                ws: None,
                sackok: None,
                ecn: None,
            },
            stats,
        ),
    }
}
