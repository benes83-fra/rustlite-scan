// tests/integration_scan.rs
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use rustls::{Certificate, PrivateKey, ServerConfig};
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task;
use tokio::time::sleep;
use tokio_rustls::rustls;
use tokio_rustls::{TlsAcceptor};
use rustlite_scan::probes::Probe;

use rustlite_scan::utils::ratelimit::RateLimiter;
use rustlite_scan::scan::scan_host;


// Type alias used in your codebase; adjust if different
type MetricsWriter = Arc<tokio::sync::Mutex<std::io::BufWriter<std::fs::File>>>;

fn make_metrics_writer(temp: &NamedTempFile) -> MetricsWriter {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(temp.path())
        .expect("open temp metrics file");
    Arc::new(tokio::sync::Mutex::new(std::io::BufWriter::new(file)))
}

#[tokio::test]
async fn scan_host_integration_smoke() {
    // 1) Start HTTP server
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let http_task = task::spawn(async move {
        loop {
            let (mut s, _) = match http_listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            // very small HTTP response with Server header
            let _ = s
                .write_all(
                    b"HTTP/1.1 200 OK\r\nServer: test-server/1.2\r\nContent-Length: 2\r\n\r\nOK",
                )
                .await;
        }
    });

    // 2) Start SSH banner server
    let ssh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ssh_addr = ssh_listener.local_addr().unwrap();
    let ssh_task = task::spawn(async move {
        loop {
            let (mut s, _) = match ssh_listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let _ = s.write_all(b"SSH-2.0-OpenSSH_8.4\r\n").await;
            // keep connection open briefly then close
            let _ = sleep(Duration::from_millis(200)).await;
        }
    });

    // 3) Start TLS server with self-signed cert (accept one connection per loop)
    let tls_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tls_addr = tls_listener.local_addr().unwrap();

    // generate self-signed cert for "localhost"
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let key_der = cert.serialize_private_key_der();
    let certs = vec![Certificate(cert_der.clone())];
    let priv_key = PrivateKey(key_der);
    let mut server_cfg = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, priv_key)
        .expect("invalid cert/key");
    server_cfg.alpn_protocols = vec![];

    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let tls_task = task::spawn(async move {
        loop {
            let (stream, _) = match tls_listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            task::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    // read a bit and respond
                    let mut buf = [0u8; 64];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls.write_all(b"OK").await;
                    let _ = sleep(Duration::from_millis(100)).await;
                }
            });
        }
    });

    // small delay to ensure servers are listening
    sleep(Duration::from_millis(100)).await;

    // 4) Prepare metrics writer (temp file)
    let temp = NamedTempFile::new().expect("temp file");
    let metrics_writer = make_metrics_writer(&temp);

    // 5) Prepare shared state required by scan_host
    // Adjust types/names if your scan_host signature differs
    let last_sent_map = Arc::new(Mutex::new(HashMap::<String, std::time::Instant>::new()));
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let global_limiter: Option<Arc<RateLimiter>> = None;
    let host_limiter: Option<Arc<RateLimiter>> = None;

    // 6) Build ports list to scan (http, ssh, tls)
    let ports = vec![http_addr.port(), ssh_addr.port(), tls_addr.port()];

    // 7) Call scan_host
    //
    // NOTE: adapt this call to match your actual scan_host signature.
    // The example below follows the signature used earlier in this conversation:
    //
    // pub async fn scan_host(
    //     ip: String,
    //     ports: &[u16],
    //     udp: bool,
    //     conc: usize,
    //     tcp_to_ms: u64,
    //     udp_to_ms: u64,
    //     udp_retries: u8,
    //     udp_backoff_ms: u64,
    //     global_limiter: Option<Arc<...>>,
    //     host_limiter: Option<Arc<...>>,
    //     host_cooldown_ms: u64,
    //     last_sent_map: Arc<Mutex<HashMap<String, Instant>>>,
    //     shutdown: Arc<std::sync::atomic::AtomicBool>,
    //     metrics_writer: Option<MetricsWriter>,
    //     cli: Arc<Cli>,
    // ) -> HostResult
    //
    // If your signature differs, adapt the call below accordingly.
    //
    // For this test we pass conservative timeouts and concurrency values.
    let ip = "127.0.0.1".to_string();

    // If your scan_host expects a Cli or other config, create a minimal test config here.
    // For convenience, if your scan_host accepts a boolean `service_probes` and probe timeouts
    // instead of a Cli, pass those values instead.
    //
    // The code below attempts to call a common variant; adapt as needed.

    // --- BEGIN: adapt this block to your scan_host signature ---
    // Example: if your scan_host accepts a Cli Arc, create a minimal Cli here.
    let http_probe = rustlite_scan::probes::http::HttpProbe {};
    let maybe_http_fp = http_probe.probe(&http_addr.ip().to_string(), http_addr.port(), 5000).await;
    println!("http probe -> {:?}", maybe_http_fp);

    let ssh_probe = rustlite_scan::probes::ssh::SshProbe {};
    let maybe_ssh_fp = ssh_probe.probe(&ssh_addr.ip().to_string(), ssh_addr.port(), 5000).await;
    println!("ssh probe -> {:?}", maybe_ssh_fp);

    let tls_probe = rustlite_scan::probes::tls::TlsProbe {};
    let maybe_tls_fp = tls_probe.probe(&tls_addr.ip().to_string(), tls_addr.port(), 5000).await;
    println!("tls probe -> {:?}", maybe_tls_fp);
    let probes = rustlite_scan::probes::default_probes();
    for p in probes.iter() {
        println!("registered probe: {}", p.name());
    }
    let cli = Arc::new(rustlite_scan::cli::Cli {
        metrics_sample: 1,
        probe_timeout_ms: 2000,
        udp_timeout_ms: 500,
        service_probes: true,
        udp: false,
        udp_burst: 100,
        udp_burst_host: 20,
        udp_rate: 0,
        udp_rate_host: 0,
        concurrency: 8,
        target: ip.clone(),
        ports: "1-65535".to_string(),
        connect_timeout_ms: 2000,
        udp_retries: 0,
        udp_retry_backoff_ms: 0,
        json: false,
        no_ping: true,
        ping_only: false,
        ping_concurrency: 100,
        ping_timeout_ms: 1000,
        json_out: String::new(),
        csv_out: String::new(),
        dry_run: false,
        metrics_out: String::new(),
        host_cooldown_ms: 0,
        force: false,
        tcp_connect_timeout_ms: 2000,

        blocklist: String::new(),
    });
    let host_result = scan_host(
        ip.clone(),
        &ports,
        false,          // udp
        8,              // concurrency
        1000,           // tcp connect timeout ms
        500,            // udp timeout ms
        0u8,            // udp_retries
        0u64,           // udp_backoff_ms
        global_limiter, // global limiter
        host_limiter,   // host limiter
        0u64,           // host_cooldown_ms
        last_sent_map.clone(),
        shutdown.clone(),
        Some(metrics_writer.clone()),
        cli,
        // If your scan_host requires a Cli/Arc<Cli>, replace the last argument with a test Cli.
    )
    .await;
    println! ("HostResult: {:?}", host_result);
    // --- END adapt block ---

    // 8) Validate HostResult and metrics file
    // If scan_host returned a HostResult, inspect fingerprints; otherwise fail the test.
    // Adjust field names if your HostResult differs.
    let hr = host_result;
    // Expect at least one fingerprint for each port we probed
    assert!(
        !hr.fingerprints.is_empty(),
        "no fingerprints returned in HostResult"
    );

    // Build a set of ports found in fingerprints
    let mut found_ports = std::collections::HashSet::new();
    for fp in &hr.fingerprints {
        found_ports.insert(fp.port);
    }
    assert!(
        found_ports.contains(&http_addr.port()),
        "http port not fingerprinted"
    );
    assert!(
        found_ports.contains(&ssh_addr.port()),
        "ssh port not fingerprinted"
    );
    assert!(
        found_ports.contains(&tls_addr.port()),
        "tls port not fingerprinted"
    );

    // Read metrics file and assert fingerprint JSON lines exist
    let mut f = File::open(temp.path()).expect("open metrics file");
    let mut contents = String::new();
    f.read_to_string(&mut contents).expect("read metrics file");
    // Expect at least one JSON line containing "service" or "evidence"
    assert!(
        contents.contains("evidence") || contents.contains("service"),
        "metrics file missing fingerprint lines"
    );

    // cleanup: drop servers by dropping listeners/tasks (they loop forever in this test)
    // In practice the test process will exit; we can abort tasks to be tidy
    http_task.abort();
    ssh_task.abort();
    tls_task.abort();
}
