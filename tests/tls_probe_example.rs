use rustlite_scan::probes::Probe;
use rustlite_scan::probes::tls::TlsProbe;

#[tokio::test]
async fn tls_probe_example_com() {
    // Probe www.example.com on port 443
    let probe = TlsProbe {};
    let fp = probe.probe("92.123.133.197", 443, 5000).await;

    // Assert we got a fingerprint
    assert!(fp.is_some(), "TLS probe failed against example.com");

    let fp = fp.unwrap();
    println!("TLS fingerprint: {:?}", fp);

    // Basic sanity: CN should not be empty
    assert!(!fp.evidence.unwrap_or_default().is_empty(), "CN evidence missing");
}
