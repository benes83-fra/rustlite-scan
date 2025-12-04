use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt,AsyncWriteExt};
use tokio::time::Duration;
use rustlite_scan::probes::Probe;   
#[tokio::test]
async fn ftp_probe_dummy_banner() {
    

    let listener = TcpListener::bind("127.0.0.1:2121").await.unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        // Send banner
        let _ = socket.write_all(b"220 dummy.ftp FTP Service Ready\r\n").await;
        // Read FEAT
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await.unwrap();
        // Respond to FEAT
        let _ = socket.write_all(b"211-Features:\r\n MDTM\r\n211 End\r\n").await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    // Run probe
    let probe = rustlite_scan::probes::ftp::FtpProbe {};
    let fp = probe.probe("127.0.0.1", 2121, 2000).await;

    assert!(fp.is_some(), "FTP probe failed");
    let evidence = fp.unwrap().evidence.unwrap();
    assert!(evidence.contains("dummy.ftp"), "Banner not captured");
    assert!(evidence.contains("Features"), "FEAT response not captured");
}
