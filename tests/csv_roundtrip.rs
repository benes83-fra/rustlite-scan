 use rustlite_scan::types;
 use rustlite_scan::scan::write_csv_file;
#[test]
fn write_csv_roundtrip() {
    use tempfile::NamedTempFile;
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    // Build a minimal HostResult
    let host = crate::types::HostResult {
        host: "127.0.0.1".into(),
        ip: "127.0.0.1".into(),
        results: vec![crate::types::PortResult { port: 53, protocol: "udp", state: "open", banner: Some("ok".into()) }],
        udp_metrics: Some(crate::types::UdpMetrics { attempts: 1, retries: 0, timeouts: 0, successes: 1, packets_sent: 1, packets_received: 1 }),
    };

    write_csv_file(&path, &[host]).unwrap();
    assert!(std::path::Path::new(&path).exists());
}
