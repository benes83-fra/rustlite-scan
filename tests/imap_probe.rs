use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Duration;
use rustlite_scan::probes::Probe;

#[tokio::test]
async fn imap_probe_dummy_banner() {
    // Start dummy IMAP server
    let listener = TcpListener::bind("127.0.0.1:2143").await.unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        // Send greeting banner
        let _ = socket.write_all(b"* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.\r\n").await;
        // Read CAPABILITY command
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await.unwrap();
        // Respond with capabilities
        let _ = socket.write_all(b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n0001 OK CAPABILITY completed\r\n").await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Run probe
    let probe = rustlite_scan::probes::imap::ImapProbe {};
    let fp = probe.probe("127.0.0.1", 2143, 2000).await.unwrap();
    let ev = fp.evidence.unwrap();

    println!("Evidence:\n{}", ev);

    // Assert normalized fields
    assert!(ev.contains("IMAP_protocol: IMAP"));
    assert!(ev.contains("IMAP_product: Dovecot"));
    assert!(ev.contains("IMAP_version: ready."));
    assert!(ev.contains("IMAP_capability: * CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN"));
}
