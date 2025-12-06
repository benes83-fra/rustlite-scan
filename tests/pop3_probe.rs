#[tokio::test]
async fn pop3_probe_dummy_banner() {
    use tokio::net::TcpListener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::Duration;
    use rustlite_scan::probes::Probe;

    let listener = TcpListener::bind("127.0.0.1:2110").await.unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        // Greeting banner
        let _ = socket.write_all(b"+OK Dovecot ready.\r\n").await;
        // Read CAPA
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await.unwrap();
        // Respond with capabilities
        let _ = socket.write_all(b"+OK Capability list follows\r\nSTLS\r\n.\r\n").await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let probe = rustlite_scan::probes::pop3::Pop3Probe {};
    let fp = probe.probe("127.0.0.1", 2110, 2000).await.unwrap();
    let ev = fp.evidence.unwrap();

    println!("Evidence:\n{}", ev);

    assert!(ev.contains("POP3_protocol: POP3"));
    assert!(ev.contains("POP3_product: Dovecot"));
    assert!(ev.contains("POP3_version: ready."));
    assert!(ev.contains("POP3_capability: +OK Capability list follows"));
}
