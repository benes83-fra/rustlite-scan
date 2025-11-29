use std::env;
use rustlite_scan::probes::udp::{udp_probe, UdpProbeStats};

#[tokio::test]
async fn real_udp_retry_opt_in() {
    if env::var("REAL_NET_TEST").is_err() {
        eprintln!("Skipping real network UDP retry test. Set REAL_NET_TEST=1 to enable.");
        return;
    }

    let ip = "8.8.8.8";
    let port = 53u16;
    let timeout_ms = 800u64;
    let retries = 2u8;
    let backoff_ms = 100u64;

    let (res, stats): (_, UdpProbeStats) = udp_probe(ip, port, timeout_ms, retries, backoff_ms, None, None).await;

    eprintln!("udp_probe result: {:?}, stats: {:?}", res, stats);

    assert!(res.state == "open" || res.banner.is_some() || res.state == "open|filtered");
    assert!(stats.attempts >= 1);
    assert!(stats.retries <= retries as u64);
}
