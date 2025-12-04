use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt,  AsyncWriteExt};
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
        println!("Waiting for EHLO...");
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await.unwrap();
        println!("Received EHLO: {}", String::from_utf8_lossy(&buf));
        // Respond to EHLO
        let _ = socket.write_all(b"250-Hello\r\n250 STARTTLS\r\n").await;
    });
    tokio::time::sleep(Duration::from_millis(1000)).await;
    // Run probe
    let probe = rustlite_scan::probes::smtp::SmtpProbe {};
    let fp = probe.probe("127.0.0.1", 2525, 2000).await;

    assert!(fp.is_some(), "SMTP probe failed");
    let evidence = fp.unwrap().evidence.unwrap();
    assert!(evidence.contains("dummy.smtp"), "Banner not captured");
    assert!(evidence.contains("STARTTLS"), "EHLO response not captured");
}
