use tokio::net::UdpSocket;
use tokio::io;
use std::time::Duration;
use rustlite_scan::probes::dns::DnsProbe;
use rustlite_scan::probes::Probe;

#[tokio::test]
async fn dns_probe_dummy_response() -> io::Result<()> {
    // Bind dummy DNS server
    let server = UdpSocket::bind("127.0.0.1:10535").await?;
    let server_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        if let Ok((n, peer)) = server.recv_from(&mut buf).await {
            println!("Dummy DNS server received {} bytes from {}", n, peer);

            // Build a minimal DNS response with rcode=0 (NOERROR)
            let mut resp = Vec::new();
            resp.extend_from_slice(&buf[..2]); // transaction ID
            resp.extend_from_slice(&[0x81, 0x80]); // flags: response, recursion available
            resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
            resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
            resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
            resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
            // Echo back the query section
            resp.extend_from_slice(&buf[12..n]);
            // Minimal TXT answer: "dummy-dns"
            resp.push(0xC0); resp.push(0x0C); // pointer to QNAME
            resp.extend_from_slice(&[0x00, 0x10]); // TYPE=TXT
            resp.extend_from_slice(&[0x00, 0x03]); // CLASS=CHAOS
            resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
            resp.extend_from_slice(&[0x00, 0x0B]); // RDLENGTH=11
            resp.push(0x0A); // TXT length=10
            resp.extend_from_slice(b"dummy-dns");

            let _ = server.send_to(&resp, peer).await;
        }
    });

    // Give server time to bind
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Run probe against dummy server
    let probe = DnsProbe {};
    let fp = probe.probe("127.0.0.1", 10535, 2000).await;

    assert!(fp.is_some(), "DNS probe failed");
    let evidence = fp.unwrap().evidence.unwrap();
    println!("Evidence: {}", evidence);
    assert!(evidence.contains("DNS response"), "Evidence did not contain DNS response");

    server_task.await?;
    Ok(())
}
