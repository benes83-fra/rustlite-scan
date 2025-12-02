// src/probes/tests/tls_probe.rs
/* 
#[cfg(test)]
mod tls_probe_tests {
    use tokio::net::TcpListener;
    use tokio::task;
    use std::sync::Arc;
    use rcgen::generate_simple_self_signed;
    use rustls::{Certificate, PrivateKey, ServerConfig, ClientConfig, RootCertStore};
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    use tokio_rustls::rustls;
    use x509_parser::prelude::*;
    use std::convert::TryFrom;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn tls_probe_parses_cert_cn_and_san_trusted_client() {
        // 1) Generate a self-signed cert for "localhost"
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.serialize_der().unwrap();
        let key_der = cert.serialize_private_key_der();

        // 2) Build rustls server config
        let certs = vec![Certificate(cert_der.clone())];
        let priv_key = PrivateKey(key_der);
        let mut server_cfg = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, priv_key)
            .expect("invalid cert/key");
        server_cfg.alpn_protocols = vec![];

        // 3) Start a TLS server on ephemeral port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

        let server_task = task::spawn(async move {
            if let Ok((stream, _peer)) = listener.accept().await {
                let mut tls = acceptor.accept(stream).await.expect("tls accept failed");
                // read a small request (if any) and then close after a short delay
                let mut buf = [0u8; 64];
                let _ = tls.read(&mut buf).await;
                let _ = tls.write_all(b"OK").await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });

        // 4) Build a client config that trusts the generated cert (add it to root store)
        let mut root_store = RootCertStore::empty();
        root_store.add(&Certificate(cert_der)).expect("add cert to root store");
        let client_cfg = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_cfg));

        // 5) Connect TCP and perform TLS handshake using the trusted connector
        let addr_str = format!("{}:{}", addr.ip(), addr.port());
        let tcp = tokio::time::timeout(Duration::from_millis(2000), tokio::net::TcpStream::connect(&addr_str))
            .await
            .expect("tcp connect timeout")
            .expect("tcp connect failed");

        // Use "localhost" as SNI (matches cert)
        let server_name = rustls::ServerName::try_from("localhost").expect("valid dnsname");
        let tls_stream = tokio::time::timeout(Duration::from_millis(2000), connector.connect(server_name, tcp))
            .await
            .expect("tls handshake timeout")
            .expect("tls handshake failed");

        // 6) Extract peer certificates and parse leaf cert
        let certs_opt = tls_stream.get_ref().1.peer_certificates();
        assert!(certs_opt.is_some() && !certs_opt.unwrap().is_empty(), "no peer certs");
        let der = &certs_opt.unwrap()[0].0;

        let (_, parsed) = x509_parser::parse_x509_certificate(der).expect("parse cert");
        let subject_cn = parsed.subject().iter_common_name().next()
            .and_then(|cn| cn.as_str().ok()).unwrap_or("").to_string();

        // SANs
        let mut sans = Vec::new();
        if let Ok(Some(ext)) = parsed.subject_alternative_name() {
            for name in ext.value.general_names.iter() {
                if let GeneralName::DNSName(d) = name {
                    sans.push(d.to_string());
                }
            }
        }

        // 7) Assertions: CN or SAN should contain "localhost"
        assert!(subject_cn.contains("localhost") || sans.iter().any(|s| s == "localhost"),
            "expected 'localhost' in CN or SANs; CN='{}' SANs={:?}", subject_cn, sans);

        // 8) Ensure server task finishes
        let _ = server_task.await;
    }
}
*/