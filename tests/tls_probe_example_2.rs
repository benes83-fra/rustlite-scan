use tokio_openssl::SslStream;
use openssl::ssl::{SslConnector, SslMethod};
use std::pin::Pin;
use rustlite_scan::probes::tls::fingerprint_tls;
#[tokio::test]
async fn tls_probe_example_com() {
    use tokio_openssl::SslStream;
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use std::pin::Pin;

    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(SslVerifyMode::NONE); // accept all certs
    let connector = builder.build();

    let ssl = connector.configure().unwrap().into_ssl("example.com").unwrap();
    let stream = tokio::net::TcpStream::connect("example.com:443").await.unwrap();
    let mut tls_stream = SslStream::new(ssl, stream).unwrap();
    let mut pinned = Pin::new(&mut tls_stream);

    if let Err(e) = pinned.as_mut().connect().await {
        panic!("Handshake failed: {:?}", e);
    }

    let fp = rustlite_scan::probes::tls::fingerprint_tls(
        "example.com",
        443,
        "https",
        "dummy negotiation".to_string(),
        tls_stream,
    )
    .await
    .unwrap();

    println!("Evidence:\n{}", fp.evidence.unwrap());
}
