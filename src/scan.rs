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
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::path::Path;
use tokio::signal;
use std::fs;


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
    ])?;

    for host in hosts {
        let (att, ret, to, succ, psent, precv) = match &host.udp_metrics {
            Some(m) => (m.attempts, m.retries, m.timeouts, m.successes, m.packets_sent, m.packets_received),
            None => (0u64, 0u64, 0u64, 0u64, 0u64, 0u64),
        };
        for port in &host.results {
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
        "host",
        "ip",
        "port",
        "protocol",
        "state",
        "banner",
        "udp_attempts",
        "udp_retries",
        "udp_timeouts",
        "udp_successes",
        "udp_packets_sent",
        "udp_packets_received",
    ])?;

    for host in hosts {
        let (att, ret, to, succ, psent, precv) = match &host.udp_metrics {
            Some(m) => (m.attempts, m.retries, m.timeouts, m.successes, m.packets_sent, m.packets_received),
            None => (0u64, 0u64, 0u64, 0u64, 0u64, 0u64),
        };

        for port in &host.results {
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
) -> HostResult {
    use futures::Future;
    use std::pin::Pin;

    // Mixed results: TCP returns PortResult, UDP returns (PortResult, UdpProbeStats)
    enum ScanItem {
        Tcp(PortResult),
        Udp((PortResult, UdpProbeStats)),
    }

    type ScanFuture = Pin<Box<dyn Future<Output = ScanItem> + Send>>;

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

    for &p in ports {
        // TCP
        {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let ip_owned = ip.clone();
            let pb_clone = pb.clone();
            tasks.push(Box::pin(async move {
                let res = tcp_probe(&ip_owned, p, tcp_to_ms).await;
                pb_clone.inc(1);
                drop(permit);
                ScanItem::Tcp(res)
            }));
        }

        // UDP
        if udp {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let ip_owned = ip.clone();
            let pb_clone = pb.clone();
            let retries = udp_retries;
            let backoff = udp_backoff_ms;
            
            // before pushing the task, capture clones
let g_lim = global_limiter.clone();
let h_lim = host_limiter.clone();
let last_sent_map = last_sent_map.clone();
let host_cooldown_ms = host_cooldown_ms;
let ip_for_task = ip_owned.clone();
let shutdown_for_task = shutdown.clone(); // if used

tasks.push(Box::pin(async move {
    // Optional: check shutdown early
    if shutdown_for_task.load(std::sync::atomic::Ordering::SeqCst) {
        // return a safe default result or skip
    }

    // Enforce per-host cooldown
    if host_cooldown_ms > 0 {
        // Acquire lock to check last timestamp
        let mut map = last_sent_map.lock().await;
        if let Some(prev) = map.get(&ip_for_task) {
            let elapsed = prev.elapsed();
            let cooldown = std::time::Duration::from_millis(host_cooldown_ms);
            if elapsed < cooldown {
                // compute remaining and drop lock before sleeping
                let remaining = cooldown - elapsed;
                drop(map);
                tokio::time::sleep(remaining).await;
                // re-lock to update timestamp
                let mut map = last_sent_map.lock().await;
                map.insert(ip_for_task.clone(), Instant::now());
            } else {
                // update timestamp immediately
                map.insert(ip_for_task.clone(), Instant::now());
            }
        } else {
            // no previous entry: insert now
            map.insert(ip_for_task.clone(), Instant::now());
        }
    }

    // Now call udp_probe with both limiters
    let res = udp_probe(&ip_for_task, p, udp_to_ms, retries, backoff, g_lim, h_lim).await;
    pb_clone.inc(1);
    drop(permit);
    ScanItem::Udp(res)
}));

          
        }
    }

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
            }
        }
    }

    pb.finish_with_message("Scan complete");

    HostResult {
        host: ip.clone(),
        ip: ip.clone(),
        results,
        udp_metrics: if udp { Some(udp_metrics) } else { None },
    }
}



// Import the per-probe stats type returned by udp_probe

