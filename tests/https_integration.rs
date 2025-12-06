use rustlite_scan::probes::https::HttpsProbe;
use rustlite_scan::probes::Probe;
#[tokio::test]
async fn https_probe_example_com() {
    let probe = HttpsProbe;
    let fp = probe.probe("example.com", 443, 5000).await.unwrap();
    let ev = fp.evidence.clone().unwrap();
    println!("Fingerprint: {:?}", fp);  
    println! ("Evidence: {}", ev);
    // Should contain cert CN or SANs
    assert!(ev.contains("TLS_subject_cn") || ev.contains("TLS_SANs"));
    // Should contain HTTP Server header or Banner
    assert!(ev.contains("Banner") || ev.contains("HTTP_Server"));
}
