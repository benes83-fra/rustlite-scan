use rustlite_scan::probes::Probe;   
use rustlite_scan::probes;
#[tokio::test]
async fn rdp_probe_vm() {
    let probe = crate::probes::rdp::RdpProbe {};
    let fp = probe.probe("192.168.178.37", 3389, 3000).await;
    assert!(fp.is_some(), "no RDP fingerprint captured");
    println!("Evidence:\n{}", fp.unwrap().evidence.unwrap());
}
