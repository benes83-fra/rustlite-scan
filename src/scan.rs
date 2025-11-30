use crate::cli::Cli;
use crate::netutils::{expand_targets, parse_ports};
use crate::types::{HostResult, PortResult, UdpMetrics};
use crate::probes::{icmp_ping_addr, tcp_probe, udp_probe};
use anyhow::Result;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;
use tokio::sync::Mutex;
use std::sync::Arc;
use std::net::IpAddr;
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use colored::*;
use serde_json::json;
use crate::utils::RateLimiter;
use std::fs::File;
use std::io::{BufWriter,Write,BufReader,BufRead};
use csv::Writer;
use crate::probes::udp::UdpProbeStats;
use cidr::IpCidr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{ Instant};
use std::collections::HashMap;
use tokio::signal;
use std::fs;
use tokio::sync::Mutex as TokioMutex;
use std::fs::OpenOptions;
use serde_json::to_string;

pub type MetricsWriter = Arc<TokioMutex<std::io::BufWriter<std::fs::File>>>;

pub fn open_metrics_writer(path: &str) -> anyhow::Result<MetricsWriter> {
    let f = OpenOptions::new().create(true).append(true).open(path)?;
    let w = std::io::BufWriter::new(f);
    Ok(Arc::new(TokioMutex::new(w)))
}

pub async fn write_metric_line(writer: &MetricsWriter, value: &crate::types::ProbeEvent) {
    // Serialize on async task to avoid blocking the runtime if needed
    let line = match serde_json::to_string(value) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut guard = writer.lock().await;
    let _ = guard.write_all(line.as_bytes());
    let _ = guard.write_all(b"\n");
    let _ = guard.flush();
}

fn load_blocklist(path: &str) -> anyhow::Result<Vec<IpCidr>> {
    let mut out = Vec::new();
    let f = File::open(path)?;
    for line in BufReader::new(f).lines() {
        let l = line?.trim().to_string();
        if l.is_empty() || l.starts_with('#') { continue; }

        // Try parse as CIDR first
        if let Ok(cidr) = l.parse::<IpCidr>() {
            out.push(cidr);
            continue;
        }

        // Try parse as single IP and convert to host CIDR
        if let Ok(ip) = l.parse::<IpAddr>() {
            // new_host creates a /32 or /128 host CIDR depending on IP version
            let cidr = IpCidr::new_host(ip);
            out.push(cidr);
            continue;
        }

        // If it's a hostname or unrecognized, ignore for now (or log)
        eprintln!("Ignoring unrecognized blocklist entry: {}", l);
    }
    Ok(out)
}



pub fn write_json_file_atomic(path: &str, value: &serde_json::Value) -> anyhow::Result<()> {
    let tmp = format!("{}.tmp", path);
    let f = File::create(&tmp)?;
    let mut w = BufWriter::new(f);
    serde_json::to_writer_pretty(&mut w, value)?;
    w.flush()?;
    // Ensure data is flushed to disk before rename (best-effort)
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        // no-op: placeholder if you want to fsync
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn write_csv_file_atomic(path: &str, hosts: &[crate::types::HostResult]) -> anyhow::Result<()> {
    let tmp = format!("{}.tmp", path);
    let f = File::create(&tmp)?;
    let mut wtr = Writer::from_writer(BufWriter::new(f));

    wtr.write_record(&[
        "host","ip","port","protocol","state","banner",
        "udp_attempts","udp_retries","udp_timeouts","udp_successes",
        "udp_packets_sent","udp_packets_received",
        "host_limiter_pps","host_limiter_burst",
        "global_limiter_pps","global_limiter_burst",
    ])?;


    for host in hosts {
        let (att, ret, to, succ, psent, precv) = match &host.udp_metrics {
            Some(m) => (m.attempts, m.retries, m.timeouts, m.successes, m.packets_sent, m.packets_received),
            None => (0u64, 0u64, 0u64, 0u64, 0u64, 0u64),
        };
        for port in &host.results {
            let host_pps = host.host_limiter.as_ref().map(|l| l.pps).unwrap_or(0);
            let host_burst = host.host_limiter.as_ref().map(|l| l.burst).unwrap_or(0);
            let global_pps = host.global_limiter.as_ref().map(|l| l.pps).unwrap_or(0);
            let global_burst = host.global_limiter.as_ref().map(|l| l.burst).unwrap_or(0);

            wtr.write_record(&[
                host.host.as_str(),
                host.ip.as_str(),
                &port.port.to_string(),
                port.protocol,
                port.state,
                port.banner.as_deref().unwrap_or(""),
                &att.to_string(),
                &ret.to_string(),
                &to.to_string(),
                &succ.to_string(),
                &psent.to_string(),
                &precv.to_string(),
                &host_pps.to_string(),
                &host_burst.to_string(),
                &global_pps.to_string(),
                &global_burst.to_string(),
            ])?;

        }
    }

    wtr.flush()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Check whether an IpAddr is contained in any blocklist CIDR
fn is_blocked(ip: &std::net::IpAddr, blocklist: &[IpCidr]) -> bool {
    blocklist.iter().any(|c| c.contains(ip))
}
// Import the per-probe stats type returned by udp_probe
pub fn write_json_file(path: &str, value: &serde_json::Value) -> anyhow::Result<()> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);
    serde_json::to_writer_pretty(&mut w, value)?;
    w.flush()?;
    Ok(())
}
pub fn write_csv_file(path: &str, hosts: &[crate::types::HostResult]) -> anyhow::Result<()> {
    let f = File::create(path)?;
    let mut wtr = Writer::from_writer(BufWriter::new(f));

    // Header
    wtr.write_record(&[
        "host","ip","port","protocol","state","banner",
        "udp_attempts","udp_retries","udp_timeouts","udp_successes",
        "udp_packets_sent","udp_packets_received",
        "host_limiter_pps","host_limiter_burst",
        "global_limiter_pps","global_limiter_burst",
    ])?;


    for host in hosts {
        let (att, ret, to, succ, psent, precv) = match &host.udp_metrics {
            Some(m) => (m.attempts, m.retries, m.timeouts, m.successes, m.packets_sent, m.packets_received),
            None => (0u64, 0u64, 0u64, 0u64, 0u64, 0u64),
        };

        for port in &host.results {
            let host_pps = host.host_limiter.as_ref().map(|l| l.pps).unwrap_or(0);
            let host_burst = host.host_limiter.as_ref().map(|l| l.burst).unwrap_or(0);
            let global_pps = host.global_limiter.as_ref().map(|l| l.pps).unwrap_or(0);
            let global_burst = host.global_limiter.as_ref().map(|l| l.burst).unwrap_or(0);

            wtr.write_record(&[
                host.host.as_str(),
                host.ip.as_str(),
                &port.port.to_string(),
                port.protocol,
                port.state,
                port.banner.as_deref().unwrap_or(""),
                &att.to_string(),
                &ret.to_string(),
                &to.to_string(),
                &succ.to_string(),
                &psent.to_string(),
                &precv.to_string(),
                &host_pps.to_string(),
                &host_burst.to_string(),
                &global_pps.to_string(),
                &global_burst.to_string(),
            ])?;

        }
    }

    wtr.flush()?;
    Ok(())
}


/// Orchestrate discovery and scanning
pub async fn run(cli: Cli) -> Result<()> {
    let ports = parse_ports(&cli.ports)?;
    let targets = expand_targets(&cli.target)?;
        // Safety validation
    if cli.concurrency == 0 || cli.concurrency > 4096 {
        anyhow::bail!("--concurrency must be between 1 and 4096");
    }
    if cli.udp_rate > 100_000 {
        anyhow::bail!("--udp-rate too large; set a lower value or use --force");
    }
    if ports.len() > 5000 && !cli.force {
        anyhow::bail!("Too many ports specified ({}). Use --force to override.", ports.len());
    }
    if targets.len() > 10_000 && !cli.force {
        anyhow::bail!("Too many targets ({}). Use --force to override.", targets.len());
    }

    
    let global_limiter: Option<Arc<RateLimiter>> = if cli.udp_rate > 0 {
        Some(RateLimiter::new(cli.udp_rate, cli.udp_burst))
    } else {
        None
    };
    let metrics_writer: Option<MetricsWriter> = if !cli.metrics_out.is_empty() {
        match open_metrics_writer(&cli.metrics_out) {
            Ok(w) => {
                eprintln!("Writing metrics to {}", &cli.metrics_out);
                Some(w)
            }
            Err(e) => {
                eprintln!("Failed to open metrics file {}: {}", &cli.metrics_out, e);
                None
            }
        }
    } else {
        None
    };

        // If dry-run, print planned limiter settings and exit
    if cli.dry_run {
        println!("Dry run: planned limiter settings");
        if let Some(gl) = &global_limiter {
            println!("  Global limiter: pps={} burst={}", gl.pps(), gl.burst());
        } else {
            println!("  Global limiter: disabled");
        }

        // For each target, show per-host limiter that would be created
        for t in &targets {
            let host_lim = if cli.udp_rate_host > 0 {
                format!("pps={} burst={}", cli.udp_rate_host, cli.udp_burst_host)
            } else {
                "disabled".to_string()
            };
            println!("  Host {} -> host_limiter: {}", t, host_lim);
        }
        return Ok(());
    }

        // Load blocklist if provided
    let blocklist: Vec<IpCidr> = if !cli.blocklist.is_empty() {
        match load_blocklist(&cli.blocklist) {
            Ok(b) => {
                eprintln!("Loaded {} blocklist entries from {}", b.len(), &cli.blocklist);
                b
            }
            Err(e) => {
                eprintln!("Failed to load blocklist {}: {}", &cli.blocklist, e);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    // Filter targets against blocklist
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let s = shutdown.clone();
        tokio::spawn(async move {
            // Wait for Ctrl-C and set shutdown flag
            if signal::ctrl_c().await.is_ok() {
                eprintln!("Received interrupt, shutting down gracefully...");
                s.store(true, Ordering::SeqCst);
            }
        });
    }
    
    // Discovery
    let blocklist_arc = Arc::new(blocklist.clone());
    let alive_hosts = if cli.no_ping {
    // filter blocklist even when skipping ping
        targets.iter()
            .filter(|t| {
                if let Ok(ip) = t.parse::<std::net::IpAddr>() {
                    !is_blocked(&ip, &blocklist)
                } else {
                    true
                }
            })
            .cloned()
            .collect::<Vec<_>>()
        } else {
        discover_hosts(&targets, cli.ping_concurrency, cli.ping_timeout_ms, blocklist_arc).await
    };


    if cli.ping_only {
        for h in &alive_hosts {
            println!("{}", h);
        }
        return Ok(());
    }
    let last_sent_map: Arc<Mutex<HashMap<String, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut all: Vec<HostResult> = Vec::new();
    let mut total_open_ports = 0usize;
    let mut host_open_counts: Vec<(String, usize)> = Vec::new();

    for ip in alive_hosts {
        if shutdown.load(Ordering::SeqCst) {
            eprintln!("Shutdown requested, stopping scan.");
            break;
        }
    // per-host limiter
        let host_limiter: Option<Arc<RateLimiter>> = if cli.udp_rate_host > 0 {
            Some(RateLimiter::new(cli.udp_rate_host, cli.udp_burst_host))
        } else {
            None
        };

        let host_result = scan_host(
            ip.clone(),
            &ports,
            cli.udp,
            cli.concurrency,
            cli.connect_timeout_ms,
            cli.udp_timeout_ms,
            cli.udp_retries,
            cli.udp_retry_backoff_ms,
            global_limiter.clone(),
            host_limiter.clone(),
            cli.host_cooldown_ms,          // NEW
            last_sent_map.clone(),         // NEW
            shutdown.clone(),              // OPTIONAL if you added it to signature
            metrics_writer.clone()
        ).await;

        all.push(host_result.clone());

        let open_count = host_result
            .results
            .iter()
            .filter(|r| r.state == "open" || r.state == "open|filtered")
            .count();
        total_open_ports += open_count;
        host_open_counts.push((host_result.ip.clone(), open_count));

        // Human output per host
        println!("Host: {}", host_result.ip.bold());
        for r in host_result.results.iter() {
            let state_colored = match r.state {
                "open" => r.state.green(),
                "open|filtered" => r.state.yellow(),
                "closed" | "filtered" | "unknown" => r.state.red(),
                _ => r.state.normal(),
            };

            let proto = r.protocol;
            let port = r.port;
            let banner = r.banner.as_deref().unwrap_or("");

            if banner.is_empty() {
                println!("  {} {:>5}  {}", proto.cyan(), port.to_string().bold(), state_colored);
            } else {
                println!(
                    "  {} {:>5}  {}  banner: {}",
                    proto.cyan(),
                    port.to_string().bold(),
                    state_colored,
                    banner.replace('\n', "\\n")
                );
            }
        }

        if let Some(m) = &host_result.udp_metrics {
            println!(
                "  {} {}",
                "UDP metrics:".bold(),
                format!(
                    "attempts={} retries={} timeouts={} successes={}",
                    m.attempts, m.retries, m.timeouts, m.successes
                )
            );
        }
        println!();
    }

    // After scanning all hosts, print summary
    println!("{}", "Scan summary".bold().underline());
    println!("  Hosts scanned: {}", all.len());
    println!(
        "  Hosts with open ports: {}",
        host_open_counts.iter().filter(|(_, c)| *c > 0).count()
    );
    println!("  Open ports:    {}", total_open_ports);

    // Print per-host open counts (sorted desc, stable by host)
    host_open_counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    println!();
    println!("{}", "Top hosts by open ports".bold());
    println!("{:40} {:>6}", "Host", "Open");
    for (host, count) in host_open_counts.iter().take(20) {
        let host_display = if *count > 0 { host.green() } else { host.normal() };
        println!("{:40} {:>6}", host_display, count);
    }

    // Aggregated JSON output (optional: print for machine use)
    // If you prefer JSON-only output, you can guard this block with a CLI flag.
    let out = json!({
        "hosts": all,
        "summary": {
            "hosts_scanned": host_open_counts.len(),
            "hosts_with_open_ports": host_open_counts.iter().filter(|(_, c)| *c > 0).count(),
            "open_ports": total_open_ports
        }
    });
    println!();
    println!("{}", serde_json::to_string_pretty(&out)?);
    // Write JSON file if requested
    if !cli.json_out.is_empty() {
        if let Err(e) = write_json_file(&cli.json_out, &out) {
            eprintln!("Failed to write JSON file {}: {}", &cli.json_out, e);
        } else {
            eprintln!("Wrote JSON output to {}", &cli.json_out);
        }
    }

    // Write CSV file if requested
    if !cli.csv_out.is_empty() {
        if let Err(e) = write_csv_file(&cli.csv_out, &all) {
            eprintln!("Failed to write CSV file {}: {}", &cli.csv_out, e);
        } else {
            eprintln!("Wrote CSV output to {}", &cli.csv_out);
        }
    if !cli.json_out.is_empty() {
        if let Err(e) = write_json_file_atomic(&cli.json_out, &out) {
            eprintln!("Failed to write JSON file {}: {}", &cli.json_out, e);
        } else {
            eprintln!("Wrote JSON output to {}", &cli.json_out);
        }
    }

    if !cli.csv_out.is_empty() {
        if let Err(e) = write_csv_file_atomic(&cli.csv_out, &all) {
            eprintln!("Failed to write CSV file {}: {}", &cli.csv_out, e);
        } else {
            eprintln!("Wrote CSV output to {}", &cli.csv_out);
        }
    }

        
}


    Ok(())
}

/// Concurrent discovery using icmp_ping_addr
///
/// - `targets`: list of host strings (IPs or hostnames)
/// - `concurrency`: max concurrent pings
/// - `timeout_ms`: per-ping timeout in milliseconds
async fn discover_hosts(
    targets: &[String],
    concurrency: usize,
    timeout_ms: u64,
    blocklist: Arc<Vec<IpCidr>>,
) -> Vec<String> {
    // Progress bar for discovery
    let pb = ProgressBar::new(targets.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} Discovering [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let sem = Arc::new(Semaphore::new(concurrency));
    let mut tasks = FuturesUnordered::new();

    for ip_str in targets {
        let ip_clone = ip_str.clone();
        let sem_clone = sem.clone();
        let pb_clone = pb.clone();
        let blocklist = blocklist.clone();

        // spawn a task per target; parse inside the task to avoid borrow issues
        tasks.push(tokio::spawn(async move {
            // small randomized delay to avoid synchronized bursts when scanning large ranges
            let jitter = rand::thread_rng().gen_range(0..50);
            tokio::time::sleep(std::time::Duration::from_millis(jitter)).await;

            match ip_clone.parse::<IpAddr>() {
                Ok(ip) => {
                    if blocklist.iter().any(|c| c.contains(&ip)) {
                        pb_clone.inc(1);
                        return (ip_clone, Some(false)); // treat as not alive / skipped
                    }
                    // acquire permit to limit concurrency
                    let _permit = sem_clone.acquire_owned().await.unwrap();
                    let alive = icmp_ping_addr(ip, timeout_ms).await;
                    pb_clone.inc(1);
                    (ip_clone, Some(alive))
                }
                Err(_) => {
                    // hostname: don't ping (or optionally try ping by name), treat as unknown -> keep for scanning
                    pb_clone.inc(1);
                    (ip_clone, None)
                }
            }
        }));
    }

    let mut alive_hosts = Vec::new();
    while let Some(res) = tasks.next().await {
        if let Ok((ip_str, maybe_alive)) = res {
            match maybe_alive {
                Some(true) => alive_hosts.push(ip_str),
                Some(false) => (), // not alive
                None => alive_hosts.push(ip_str), // hostname fallback: keep for scanning
            }
        }
    }

    pb.finish_with_message("Discovery complete");
    alive_hosts
}

/// Per-host scanning: calls probes from modules and aggregates per-host UDP metrics
/// Per-host scanning: calls probes from modules and aggregates per-host UDP metrics
pub async fn scan_host(
    ip: String,
    ports: &[u16],
    udp: bool,
    conc: usize,
    tcp_to_ms: u64,
    udp_to_ms: u64,
    udp_retries: u8,
    udp_backoff_ms: u64,
    global_limiter: Option<Arc<RateLimiter>>,
    host_limiter: Option<Arc<RateLimiter>>,
    host_cooldown_ms: u64,                                 // NEW
    last_sent_map: Arc<Mutex<HashMap<String, Instant>>>,   // NEW
    shutdown: Arc<std::sync::atomic::AtomicBool>,          // OPTIONAL: if you want to check shutdown inside scan_host
    metrics_writer: Option<MetricsWriter>,                 // OPTIONAL: if you want to write per-probe metrics
) -> HostResult {
    use futures::Future;
    use std::pin::Pin;

    // Mixed results: TCP returns PortResult, UDP returns (PortResult, UdpProbeStats)
    enum ScanItem {
        Tcp(PortResult),
        Udp((PortResult, UdpProbeStats)),
    }

    type ScanFuture = Pin<Box<dyn Future<Output = ScanItem> + Send>>;

    // concurrency semaphore
    let semaphore = Arc::new(Semaphore::new(conc));

    let mut tasks = FuturesUnordered::<ScanFuture>::new();

    let total = ports.len() as u64 * if udp { 2 } else { 1 };
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    // Per-port loop: spawn TCP and (optionally) UDP tasks.
    for &p in ports {
        // Respect shutdown if requested
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        // Acquire a permit before spawning tasks to limit concurrency
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        // Per-iteration clones of shared optional handles so each closure gets its own Arc
        let metrics_writer_call = metrics_writer.clone();
        let host_limiter_call = host_limiter.clone();
        let global_limiter_call = global_limiter.clone();

        // Per-iteration owned values
        let ip_for_tcp = ip.clone();
        let pb_for_tcp = pb.clone();

        // TCP task
        tasks.push(Box::pin({
            // Move only per-iteration clones into the closure
            let ip_for_tcp = ip_for_tcp.clone();
            let pb_for_tcp = pb_for_tcp.clone();
           
            let metrics_writer_call = metrics_writer_call.clone();
            let host_limiter_call = host_limiter_call.clone();
            let global_limiter_call = global_limiter_call.clone();

            async move {
                let res = tcp_probe(&ip_for_tcp, p, tcp_to_ms).await;
                

                if let Some(w) = metrics_writer_call.clone() {
                    let event = crate::types::ProbeEvent {
                        ts: chrono::Utc::now(),
                        host: ip_for_tcp.clone(),
                        ip: ip_for_tcp.clone(),
                        port: p,
                        protocol: "tcp".to_string(),
                        outcome: res.state.to_string(),
                        duration_ms: None,
                        banner: res.banner.clone(),
                        udp_attempts: None,
                        udp_retries: None,
                        udp_timeouts: None,
                        udp_successes: None,
                        udp_packets_sent: None,
                        udp_packets_received: None,
                        host_limiter_pps: host_limiter_call.as_ref().map(|h| h.pps()),
                        host_limiter_burst: host_limiter_call.as_ref().map(|h| h.burst()),
                        global_limiter_pps: global_limiter_call.as_ref().map(|g| g.pps()),
                        global_limiter_burst: global_limiter_call.as_ref().map(|g| g.burst()),
                        note: None,
                    };
                    write_metric_line(&w, &event).await;
                }

                pb_for_tcp.inc(1);
                drop(permit);
                ScanItem::Tcp(res)
            }
        }));

        // If UDP scanning is enabled, spawn a UDP task for the same port
        if udp {
            // Acquire a second permit for the UDP probe (keeps concurrency semantics similar to original)
            let permit2 = semaphore.clone().acquire_owned().await.unwrap();

            // Per-iteration clones for UDP closure
            let ip_for_udp = ip.clone();
            let pb_for_udp = pb.clone();
            let metrics_writer_call2 = metrics_writer.clone();
            let host_limiter_call2 = host_limiter.clone();
            let global_limiter_call2 = global_limiter.clone();

            tasks.push(Box::pin({
                let ip_for_udp = ip_for_udp.clone();
                let pb_for_udp = pb_for_udp.clone();
                
                let metrics_writer_call2 = metrics_writer_call2.clone();
                let host_limiter_call2 = host_limiter_call2.clone();
                let global_limiter_call2 = global_limiter_call2.clone();

                async move {
                    // Clone limiters for the probe call so the probe can take ownership
                    let g_lim_call = global_limiter_call2.clone();
                    let h_lim_call = host_limiter_call2.clone();

                    let (r, stats) = udp_probe(&ip_for_udp, p, udp_to_ms, udp_retries, udp_backoff_ms, g_lim_call, h_lim_call).await;

                    if let Some(w) = metrics_writer_call2.clone() {
                        let event = crate::types::ProbeEvent {
                            ts: chrono::Utc::now(),
                            host: ip_for_udp.clone(),
                            ip: ip_for_udp.clone(),
                            port: p,
                            protocol: "udp".to_string(),
                            outcome: r.state.to_string(),
                            duration_ms: None,
                            banner: r.banner.clone(),
                            udp_attempts: Some(stats.attempts),
                            udp_retries: Some(stats.retries),
                            udp_timeouts: Some(stats.timeouts),
                            udp_successes: Some(stats.successes),
                            udp_packets_sent: Some(stats.packets_sent),
                            udp_packets_received: Some(stats.packets_received),
                            host_limiter_pps: host_limiter_call2.as_ref().map(|h| h.pps()),
                            host_limiter_burst: host_limiter_call2.as_ref().map(|h| h.burst()),
                            global_limiter_pps: global_limiter_call2.as_ref().map(|g| g.pps()),
                            global_limiter_burst: global_limiter_call2.as_ref().map(|g| g.burst()),
                            note: None,
                        };
                        write_metric_line(&w, &event).await;
                    }

                    pb_for_udp.inc(1);
                    drop(permit2);
                    ScanItem::Udp((r, stats))
                }
            }));
        }
    } // end for ports

    // Collect results
    let mut results: Vec<PortResult> = Vec::new();
    let mut udp_metrics = UdpMetrics::default();

    while let Some(item) = tasks.next().await {
        match item {
            ScanItem::Tcp(r) => results.push(r),
            ScanItem::Udp((r, stats)) => {
                results.push(r);
                udp_metrics.attempts += stats.attempts;
                udp_metrics.retries += stats.retries;
                udp_metrics.timeouts += stats.timeouts;
                udp_metrics.successes += stats.successes;
                udp_metrics.packets_sent += stats.packets_sent;
                udp_metrics.packets_received += stats.packets_received;
            }
        }
    }

    pb.finish_with_message("Scan complete");

    // Build limiter info for diagnostics
    let host_lim_info = host_limiter.as_ref().map(|hl| crate::types::LimiterInfo {
        pps: hl.pps(),
        burst: hl.burst(),
    });
    let global_lim_info = global_limiter.as_ref().map(|gl| crate::types::LimiterInfo {
        pps: gl.pps(),
        burst: gl.burst(),
    });

    HostResult {
        host: ip.clone(),
        ip: ip.clone(),
        results,
        udp_metrics: if udp { Some(udp_metrics) } else { None },
        host_limiter: host_lim_info,
        global_limiter: global_lim_info,
    }
}




// Import the per-probe stats type returned by udp_probe

