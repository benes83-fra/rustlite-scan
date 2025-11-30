use tempfile::tempdir;
use rustlite_scan::scan::{open_metrics_writer, write_metric_line};
use rustlite_scan::types::ProbeEvent;
use std::io::Write;
use tokio::time::Duration;

#[tokio::test]
async fn metrics_out_writes_jsonl() {
    // Create a temp directory and a path inside it (avoids NamedTempFile locking on Windows)
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("metrics.jsonl");
    let path_str = path.to_str().unwrap().to_string();

    // Open the metrics writer (Arc<TokioMutex<BufWriter<File>>>)
    let writer = open_metrics_writer(&path_str).expect("open_metrics_writer");

    // Build a minimal ProbeEvent (fill required fields)
    let event = ProbeEvent {
        ts: chrono::Utc::now(),
        host: "127.0.0.1".to_string(),
        ip: "127.0.0.1".to_string(),
        port: 12345,
        protocol: "udp".to_string(),
        outcome: "sent".to_string(),
        duration_ms: Some(0),
        banner: None,
        udp_attempts: Some(1),
        udp_retries: Some(0),
        udp_timeouts: Some(0),
        udp_successes: Some(0),
        udp_packets_sent: Some(1),
        udp_packets_received: Some(0),
        host_limiter_pps: None,
        host_limiter_burst: None,
        global_limiter_pps: None,
        global_limiter_burst: None,
        note: None,
    };

    // Write one line
    write_metric_line(&writer, &event).await;

    // Ensure buffered data is flushed to disk while holding the mutex
    {
        let mut guard = writer.lock().await;
        guard.flush().expect("flush");
    }

    // Drop the Arc so the file handle is released (important on Windows)
    drop(writer);

    // Small yield to ensure OS has released handles (usually not needed, but safe)
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Read file and assert it contains at least one JSON line
    let s = std::fs::read_to_string(&path_str).expect("read file");
    assert!(s.lines().next().is_some(), "metrics file should contain at least one line");
}
