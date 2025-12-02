// tests/logging_smoke.rs
use std::sync::Arc;
use rustlite_scan;
use rustlite_scan::cli::Cli;
#[tokio::test]
async fn logging_smoke() {
    // initialize tracing so debug logs show
    rustlite_scan::init_tracing();

    // pick a port that is almost always open locally: 22 (SSH) or 80/443 if you run a web server
    let ip = "127.0.0.1".to_string();
    let ports = vec![22]; // adjust to a port you know is open

    // call scan_host with probes enabled
    let hr = rustlite_scan::scan::scan_host(
        ip.clone(),
        &ports,
        false,              // udp
        4,                  // concurrency
        2000,               // tcp timeout ms
        0,                  // udp timeout ms
        0,                  // udp retries
        0,                  // udp backoff
        None,               // global limiter
        None,               // host limiter
        0,                  // host cooldown
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        None,               // metrics writer
        Arc::new(crate::Cli { service_probes: true, probe_timeout_ms: 2000, metrics_sample: 1, ..Default::default() }),
    ).await;

    println!("HostResult: {:#?}", hr);
}
