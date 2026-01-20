use tempfile::NamedTempFile;
use std::fs;
use std::io::Read;
use rustlite_scan::scan::{write_csv_file, write_csv_file_atomic};
use rustlite_scan::types::{HostResult, PortResult, UdpMetrics};

#[test]
fn csv_roundtrip_flexible() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let host = HostResult {
        host: "127.0.0.1".into(),
        ip: "127.0.0.1".into(),
        results: vec![
            PortResult { port: 53, protocol: "udp", state: "open", banner: Some("ok".into()),ttl: None, window_size :None, mss: None, df: None }
        ],
        udp_metrics: Some(UdpMetrics { attempts: 1, retries: 0, timeouts: 0, successes: 1, packets_sent: 1, packets_received: 1 }),
        host_limiter: None,
        global_limiter: None,
        fingerprints: Vec::new(),
    };

    write_csv_file(&path, &[host.clone()]).unwrap();

    let mut s = String::new();
    fs::File::open(&path).unwrap().read_to_string(&mut s).unwrap();

    // Ensure required columns exist
    assert!(s.contains("host,ip,port,protocol,state,banner"), "missing required CSV header columns");

    // Ensure row for port exists
    assert!(s.contains("127.0.0.1,127.0.0.1,53,udp,open,ok"), "row not found");

    // Also test atomic writer
    let tmp2 = NamedTempFile::new().unwrap();
    let path2 = tmp2.path().to_str().unwrap().to_string();
    write_csv_file_atomic(&path2, &[host]).unwrap();
    let mut s2 = String::new();
    fs::File::open(&path2).unwrap().read_to_string(&mut s2).unwrap();
    assert!(s2.contains("host,ip,port,protocol,state,banner"));
}
