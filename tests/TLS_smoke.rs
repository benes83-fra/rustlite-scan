use rustlite_scan::probes::{ Probe};
#[tokio::test]
async fn tls_probe_example_com() {
    let probe= rustlite_scan::probes::tls::TlsProbe {};
    let fp = probe.probe("www.example.com", 443, 5000).await; // example.com IP

    println!("Fingerprint: {:?}", fp);
    assert!(fp.is_some(), "TLS probe failed against example.com");
}
