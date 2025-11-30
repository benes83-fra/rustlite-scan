use rustlite_scan::probes;
use rustlite_scan::probes::Probe;
#[tokio::test]
async fn ssh_probe_reads_banner() {
    use tokio::net::TcpListener;
    use tokio::io::AsyncWriteExt;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // spawn a server that writes an SSH banner then closes
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            let _ = s.write_all(b"SSH-2.0-OpenSSH_8.4\r\n").await;
            // keep connection open briefly
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    });

    let probe = crate::probes::ssh::SshProbe {};
    let fp = probe.probe(&addr.ip().to_string(), addr.port(), 1000).await;
    assert!(fp.is_some());
    let fp = fp.unwrap();
    assert!(fp.evidence.unwrap_or_default().contains("SSH-2.0"));
}
