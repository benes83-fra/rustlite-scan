#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio::io::AsyncWriteExt;
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
    use std::sync::Arc;
    use rustlite_scan::probes::https::HttpsProbe;
    use rustlite_scan::probes::Probe;

    #[tokio::test]
    async fn https_probe_captures_cert_and_server_header() {
        // 1. Build a TLS acceptor with a self-signed cert
        let mut acceptor_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor_builder.set_private_key_file("tests/server.key", SslFiletype::PEM).unwrap();
        acceptor_builder.set_certificate_chain_file("tests/server.crt").unwrap();
        let acceptor = Arc::new(acceptor_builder.build());

        // 2. Start a local listener
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor_clone = acceptor.clone();

        // 3. Spawn a task to accept one connection and send a fixed HTTP response
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ssl = openssl::ssl::Ssl::new(acceptor_clone.context()).unwrap();
            let mut stream = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
            tokio::pin!(stream);
            //let mut pinned = Box::pin(stream);
            stream.as_mut().accept().await.unwrap();
            let resp = b"HTTP/1.0 200 OK\r\nServer: TestServer\r\n\r\nHello";
            stream.as_mut().write_all(resp).await.unwrap();
        });

        // 4. Run the probe against the local TLS server
        let probe = HttpsProbe;
        let fp = probe.probe("127.0.0.1", port, 2000).await.unwrap();

        // 5. Assert evidence contains cert CN and Server header
        let ev = fp.evidence.unwrap();
        assert!(ev.contains("TLS_subject_cn"));
        assert!(ev.contains("HTTP_Server: TestServer"));
    }
}
