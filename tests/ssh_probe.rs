use rustlite_scan::probes;
use rustlite_scan::probes::Probe;

#[tokio::test]
async fn ssh_probe_reads_banner() {
    use tokio::net::TcpListener;
    use tokio::io::AsyncWriteExt;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // spawn a server that writes an SSH banner then keeps the connection open briefly
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            let _ = s.write_all(b"SSH-2.0-OpenSSH_8.4\r\n").await;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    });

    let probe = crate::probes::ssh::SshProbe {};
    let fp = probe.probe(&addr.ip().to_string(), addr.port(), 1000).await;
    assert!(fp.is_some(), "no SSH fingerprint captured");

    let fp = fp.unwrap();
    let ev = fp.evidence.unwrap_or_default();
    println!("Evidence:\n{}", ev);

    // Assert on normalized fields
    assert!(ev.contains("SSH_protocol: SSH-2.0"), "missing SSH protocol");
    assert!(ev.contains("SSH_product: OpenSSH"), "missing SSH product");
    assert!(ev.contains("SSH_version: 8.4"), "missing SSH version");
    // comment field is optional, so we don’t hard‑fail if absent
}
