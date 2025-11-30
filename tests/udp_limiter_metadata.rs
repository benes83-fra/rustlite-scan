
use rustlite_scan::utils::RateLimiter;
use rustlite_scan::probes::udp::udp_probe;
use rustlite_scan::probes::udp::UdpProbeStats;
use std::env;

#[tokio::test]
async fn udp_probe_includes_limiter_metadata() {
    // This test is safe and local-first; if REAL_NET_TEST is not set, use localhost and a likely-closed port.
    let target = if env::var("REAL_NET_TEST").is_ok() { "8.8.8.8" } else { "127.0.0.1" };
    let port = 53535u16; // unlikely to be open; we only check metadata

    // Create tiny limiters
    let host_limiter = Some(RateLimiter::new(5, 2)); // 5 pps, burst 2
    let global_limiter = Some(RateLimiter::new(10, 4)); // 10 pps, burst 4

    let (_res, stats): (_, UdpProbeStats) = udp_probe(
        target,
        port,
        200,   // timeout_ms
        0,     // retries
        10,    // backoff_ms
        global_limiter.clone(),
        host_limiter.clone(),
    ).await;

    // Assert metadata is present and matches configured values
    assert_eq!(stats.host_limiter_pps, Some(5));
    assert_eq!(stats.host_limiter_burst, Some(2));
    assert_eq!(stats.global_limiter_pps, Some(10));
    assert_eq!(stats.global_limiter_burst, Some(4));
}
