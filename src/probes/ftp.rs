// src/probes/ftp.rs
use super::Probe;
use crate::probes::ProbeContext;
use crate::service::ServiceFingerprint; // adapt path if needed
use async_trait::async_trait;
use openssl::ssl::{SslConnector, SslMethod};
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{timeout, Instant};
use tokio_openssl::SslStream;

pub struct FtpProbe;

#[async_trait]
impl Probe for FtpProbe {
    async fn probe_with_ctx(
        &self,
        ip: &str,
        port: u16,
        ctx: ProbeContext,
    ) -> Option<ServiceFingerprint> {
        let timeout_ms = ctx
            .get("timeout_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(2000);
        self.probe(ip, port, timeout_ms).await
    }
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let addr = format!("{}:{}", ip, port);
        let connect_deadline = Duration::from_millis(timeout_ms);

        let stream = match timeout(connect_deadline, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };

        // Adaptive banner timeout: max(3s, 10 * connect_rtt)
        let connect_rtt = Duration::from_millis(1); // placeholder
        let banner_overall = {
            let adaptive = connect_rtt
                .checked_mul(10)
                .unwrap_or(Duration::from_secs(0));
            let min = Duration::from_secs(3);
            if adaptive > min {
                adaptive
            } else {
                min
            }
        };

        let mut evidence = String::new();
        let mut reader = BufReader::new(stream);

        // Banner
        if let Some(b) =
            read_banner_with_retries(&mut reader, banner_overall, Duration::from_millis(500)).await
        {
            push_line(&mut evidence, "Banner", b.trim());
            eprintln!("FTP Banner: {}", b.trim());
        }

        // Try AUTH TLS inline
        if reader.get_mut().write_all(b"AUTH TLS\r\n").await.is_ok() {
            if let Some(reply) = read_until_final_reply(
                &mut reader,
                Duration::from_millis(500),
                Duration::from_secs(3),
            )
            .await
            {
                push_line(&mut evidence, "AUTH_TLS_reply", reply.trim());
                if reply.starts_with("234") {
                    // AUTH TLS accepted -> consume reader, perform handshake inline, then reconstruct a BufReader over SslStream
                    let tcp = reader.into_inner();

                    // Build OpenSSL connector (reuse your tls.rs config if you want)
                    let builder = match SslConnector::builder(SslMethod::tls()) {
                        Ok(b) => b,
                        Err(e) => {
                            eprintln!("ssl builder error: {}", e);
                            return Some(ServiceFingerprint::from_banner(
                                ip, port, "ftp", evidence,
                            ));
                        }
                    };
                    let connector = builder.build();
                    let ssl = match connector.configure() {
                        Ok(cfg) => match cfg.into_ssl(ip) {
                            Ok(s) => s,
                            Err(e) => {
                                eprintln!("into_ssl error: {}", e);
                                return Some(ServiceFingerprint::from_banner(
                                    ip, port, "ftp", evidence,
                                ));
                            }
                        },
                        Err(e) => {
                            eprintln!("ssl configure error: {}", e);
                            return Some(ServiceFingerprint::from_banner(
                                ip, port, "ftp", evidence,
                            ));
                        }
                    };

                    // Create SslStream and handshake
                    let ssl_stream = match SslStream::new(ssl, tcp) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("failed to create SslStream: {}", e);
                            return Some(ServiceFingerprint::from_banner(
                                ip, port, "ftp", evidence,
                            ));
                        }
                    };

                    // Pin and perform async handshake
                    let mut pinned = Box::pin(ssl_stream);
                    if let Err(e) = pinned.as_mut().connect().await {
                        eprintln!("TLS handshake failed: {}", e);
                        return Some(ServiceFingerprint::from_banner(ip, port, "ftp", evidence));
                    }

                    // Extract cert info (optional)
                    if let Some(cert) = pinned.ssl().peer_certificate() {
                        if let Some(entry) = cert
                            .subject_name()
                            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                            .next()
                        {
                            if let Ok(data) = entry.data().as_utf8() {
                                let cn = data.to_string();
                                push_line(&mut evidence, "TLS_subject_cn", cn.trim());
                            }
                        }
                        if let Some(san_stack) = cert.subject_alt_names() {
                            let mut s = String::new();
                            for gen in san_stack.iter() {
                                if let Some(dns) = gen.dnsname() {
                                    if !s.is_empty() {
                                        s.push_str(", ");
                                    }
                                    s.push_str(dns);
                                }
                            }
                            if !s.is_empty() {
                                push_line(&mut evidence, "TLS_SANs", &s);
                            }
                        }
                        push_line(
                            &mut evidence,
                            "TLS_not_before",
                            &cert.not_before().to_string(),
                        );
                        push_line(
                            &mut evidence,
                            "TLS_not_after",
                            &cert.not_after().to_string(),
                        );
                    }

                    // Convert Pin<Box<SslStream<TcpStream>>> -> Box<SslStream<TcpStream>>
                    let boxed_ssl: Box<SslStream<TcpStream>> = Pin::into_inner(pinned);

                    // Take ownership of the inner SslStream
                    let ssl_stream_owned: SslStream<TcpStream> = *boxed_ssl;

                    // Wrap in BufReader and continue over TLS
                    let mut tls_reader = BufReader::new(ssl_stream_owned);

                    // SYST over TLS
                    if tls_reader.get_mut().write_all(b"SYST\r\n").await.is_ok() {
                        if let Some(syst) = read_until_final_reply(
                            &mut tls_reader,
                            Duration::from_millis(300),
                            Duration::from_secs(2),
                        )
                        .await
                        {
                            push_line(&mut evidence, "SYST", syst.trim());
                        }
                    }

                    // FEAT over TLS
                    if tls_reader.get_mut().write_all(b"FEAT\r\n").await.is_ok() {
                        if let Some(feat) = read_feat_with_reader(
                            &mut tls_reader,
                            Duration::from_secs(5),
                            Duration::from_millis(300),
                        )
                        .await
                        {
                            push_line(&mut evidence, "FEAT", feat.trim());
                        }
                    }

                    // Continue with NOOP or other commands as needed...
                    return Some(ServiceFingerprint::from_banner(ip, port, "ftp", evidence));
                } else {
                    // AUTH TLS rejected; continue plain-text below
                }
            } else {
                eprintln!("AUTH TLS reply timed out");
            }
        }

        // Plain-text SYST
        if reader.get_mut().write_all(b"SYST\r\n").await.is_ok() {
            if let Some(s) = read_until_final_reply(
                &mut reader,
                Duration::from_millis(300),
                Duration::from_secs(2),
            )
            .await
            {
                push_line(&mut evidence, "SYST", s.trim());
            }
        }

        // Plain-text FEAT
        if reader.get_mut().write_all(b"FEAT\r\n").await.is_ok() {
            if let Some(f) = read_feat_with_reader(
                &mut reader,
                Duration::from_secs(5),
                Duration::from_millis(300),
            )
            .await
            {
                push_line(&mut evidence, "FEAT", f.trim());
            }
        }

        // NOOP (harmless)
        if reader.get_mut().write_all(b"NOOP\r\n").await.is_ok() {
            if let Some(n) = read_until_final_reply(
                &mut reader,
                Duration::from_millis(200),
                Duration::from_secs(1),
            )
            .await
            {
                push_line(&mut evidence, "NOOP", n.trim());
            }
        }

        if evidence.is_empty() {
            return None;
        }

        Some(ServiceFingerprint::from_banner(ip, port, "ftp", evidence))
    }

    fn ports(&self) -> Vec<u16> {
        vec![21]
    }
    fn name(&self) -> &'static str {
        "ftp"
    }
}

// -------------------- Helpers --------------------

// Generic read_line_timeout that works with BufReader<TcpStream> and BufReader<SslStream<TcpStream>>
async fn read_line_timeout<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    dur: Duration,
) -> Option<String> {
    let mut line = String::new();
    match timeout(dur, reader.read_line(&mut line)).await {
        Ok(Ok(0)) => None, // EOF
        Ok(Ok(_)) => {
            log_raw_preview(&line);
            Some(line)
        }
        _ => None, // timeout or error
    }
}

// Read banner with repeated short attempts until overall timeout elapses.
async fn read_banner_with_retries<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    overall: Duration,
    per_try: Duration,
) -> Option<String> {
    let start = Instant::now();
    while start.elapsed() < overall {
        if let Some(line) = read_line_timeout(reader, per_try).await {
            return Some(line);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

// Read until a final reply line is seen (NNN<space>) or overall timeout.
async fn read_until_final_reply<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    per_line: Duration,
    overall: Duration,
) -> Option<String> {
    let start = Instant::now();
    let mut last = String::new();

    while start.elapsed() < overall {
        match read_line_timeout(reader, per_line).await {
            Some(line) => {
                last = line.clone();
                if line.as_bytes().len() >= 4 && line.as_bytes()[3] == b' ' {
                    return Some(last);
                }
            }
            None => break,
        }
    }
    if last.is_empty() {
        None
    } else {
        Some(last)
    }
}

// Read FEAT reply robustly (generic reader)
async fn read_feat_with_reader<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    overall: Duration,
    per_line: Duration,
) -> Option<String> {
    let start = Instant::now();
    let mut out = String::new();

    // Read first line
    let first = match read_line_timeout(reader, per_line).await {
        Some(f) => f,
        None => return None,
    };
    out.push_str(&first);

    // Check multiline 211- reply
    if first.as_bytes().len() >= 4
        && &first.as_bytes()[0..3] == b"211"
        && first.as_bytes()[3] == b'-'
    {
        while start.elapsed() < overall {
            match read_line_timeout(reader, per_line).await {
                Some(l) => {
                    out.push_str(&l);
                    if l.as_bytes().len() >= 4
                        && &l.as_bytes()[0..3] == b"211"
                        && l.as_bytes()[3] == b' '
                    {
                        break;
                    }
                }
                None => break,
            }
        }
    }

    Some(out)
}

// Small helper to append labeled lines to evidence
fn push_line(out: &mut String, label: &str, value: &str) {
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(label);
    out.push_str(": ");
    out.push_str(value);
}

// Small debug helper: print a short escaped preview of the read line to stderr.
fn log_raw_preview(s: &str) {
    let preview: String = s
        .chars()
        .take(200)
        .map(|c| match c {
            '\r' => '\\',
            '\n' => '↵',
            _ => c,
        })
        .collect();
    eprintln!("raw read preview: {}", preview);
}
