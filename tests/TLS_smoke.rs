use rustlite_scan::probes::{ Probe};
#[tokio::test]
async fn tls_probe_example_com() {
    let probe= rustlite_scan::probes::tls::TlsProbe {};
    let fp = probe.probe("93.184.216.34", 443, 3000).await; // example.com IP
    assert!(fp.is_some(), "TLS probe failed against example.com");
}
