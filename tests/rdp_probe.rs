use rustlite_scan::probes::Probe;
use rustlite_scan::probes;
#[tokio::test]

async fn rdp_probe_localhost() {
    let probe = crate::probes::rdp::RdpProbe {};
    let fp = probe.probe("127.0.0.1", 3389, 2000).await;
    assert!(fp.is_some(), "no RDP fingerprint captured");
    println!("Evidence:\n{}", fp.unwrap().evidence.unwrap());
}
