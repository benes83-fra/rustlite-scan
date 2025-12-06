use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Duration;
use rustlite_scan::probes::Probe;

#[tokio::test]
async fn smtp_probe_dummy_banner() {
    // Start dummy SMTP server
    let listener = TcpListener::bind("127.0.0.1:2525").await.unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        // Send banner
        let _ = socket.write_all(b"220 dummy.smtp ESMTP Service Ready\r\n").await;
        // Read EHLO
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await.unwrap();
        // Respond to EHLO
        let _ = socket.write_all(b"250-Hello\r\n250 STARTTLS\r\n").await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Run probe
    let probe = rustlite_scan::probes::smtp::SmtpProbe {};
    let fp = probe.probe("127.0.0.1", 2525, 2000).await.unwrap();
    let ev = fp.evidence.unwrap();

    println!("Evidence:\n{}", ev);

    // Assert normalized fields
    assert!(ev.contains("SMTP_protocol: SMTP"));
    assert!(ev.contains("SMTP_product: ESMTP"));
    assert!(ev.contains("SMTP_comment: dummy.smtp"));
    assert!(ev.contains("SMTP_version: Service Ready"));
}
