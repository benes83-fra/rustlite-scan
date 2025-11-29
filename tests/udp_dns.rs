use std::env;
use rustlite_scan::probes::udp::{udp_probe, UdpProbeStats};

#[tokio::test]
async fn real_udp_dns_test_opt_in() {
    if env::var("REAL_NET_TEST").is_err() {
        eprintln!("Skipping real network UDP DNS test. Set REAL_NET_TEST=1 to enable.");
        return;
    }

    let ip = "8.8.8.8";
    let port = 53u16;
    let timeout_ms = 1200u64;
    let retries = 1u8;
    let backoff_ms = 50u64;

    let (res, stats): (_, UdpProbeStats) = udp_probe(ip, port, timeout_ms, retries, backoff_ms, None, None).await;

    eprintln!("udp_probe result: {:?}, stats: {:?}", res, stats);

    assert!(res.state == "open" || res.banner.is_some(), "expected DNS response or banner");
    assert!(stats.attempts >= 1);
}
