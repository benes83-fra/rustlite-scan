use crate::service::ServiceFingerprint;
use crate::types::PortResult;

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq)]
enum TlsStack {
    OpenSsl,
    BoringSsl,
    GoTls,
    Nss,
    Java,
    Rustls,
    Unknown,
}

fn dedupe_lines(s: &str) -> String {
    let mut set = BTreeSet::new();
    for line in s.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            set.insert(trimmed.to_string());
        }
    }
    set.into_iter().collect::<Vec<_>>().join("\n")
}

#[derive(Debug, Clone)]
pub struct SynAckFp {
    pub ttl: Option<u8>,
    pub window: Option<u32>,
    pub mss: Option<u16>,
    pub df: Option<bool>,

    pub ts: Option<bool>,
    pub ws: Option<u8>,
    pub sackok: Option<bool>,
    pub ecn: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct RstFp {
    pub ttl: Option<u8>,
    pub window: Option<u32>,
    pub df: Option<bool>,
}

impl SynAckFp {
    pub fn from_port(p: &PortResult) -> Self {
        SynAckFp {
            ttl: p.ttl,
            window: p.window_size,
            mss: p.mss,
            df: p.df,
            ts: p.ts,
            ws: p.ws,
            sackok: p.sackok,
            ecn: p.ecn,
        }
    }
}

impl RstFp {
    pub fn from_port(p: &PortResult) -> Self {
        RstFp {
            ttl: p.ttl,
            window: p.window_size,
            df: p.df,
        }
    }
}
#[derive(Debug, Clone)]
struct OsSynFp {
    ttl: u8,
    window: u32,
    mss: Option<u16>,
    df: bool,
    ts: Option<bool>,
    ws: Option<u8>,
    sackok: Option<bool>,
    ecn: Option<bool>,
}

#[derive(Debug, Clone)]
struct OsRstFp {
    ttl: u8,
    window: u32,
    df: bool,
}

#[derive(Debug, Clone)]
struct OsFingerprint {
    name: &'static str,
    syn: OsSynFp,
    rst: OsRstFp,
}

pub fn infer_os(
    ip: &str,
    ports: &[PortResult],
    service_fps: &[ServiceFingerprint],
) -> Option<ServiceFingerprint> {
    // ------------------------------
    // 1. Collect open ports
    // ------------------------------
    let mut ports_mut = ports.to_vec();
    apply_tcp_syn_to_ports(&mut ports_mut, service_fps);

    // Extract SYN/ACK fingerprint (from any open TCP port)
    let syn_fp = ports_mut
        .iter()
        .find(|p| p.protocol == "tcp" && p.state == "open")
        .map(SynAckFp::from_port);

    // Extract RST fingerprint (from any closed TCP port)
    let rst_fp = ports_mut
        .iter()
        .find(|p| p.protocol == "tcp" && p.state == "closed")
        .map(RstFp::from_port);
    // ------------------------------
    // SYN/ACK + RST fingerprint scoring
    // ------------------------------
    let mut synrst_best_os = None;
    let mut synrst_best_score = 0;

    if let Some(ref syn) = syn_fp {
        for os in os_fingerprint_table() {
            let mut score = score_syn(syn, &os.syn);

            if let Some(ref rst) = rst_fp {
                score += score_rst(rst, &os.rst);
            }

            if score > synrst_best_score {
                synrst_best_score = score;
                synrst_best_os = Some(os.name);
            }
        }
    }

    let mut open_ports: Vec<u16> = ports_mut
        .iter()
        .filter(|r| r.protocol == "tcp" && r.state == "open")
        .map(|r| r.port)
        .collect();

    open_ports.sort_unstable();
    open_ports.dedup();

    if open_ports.is_empty() {
        return None;
    }

    // ------------------------------
    // 2. Base scores from ports
    // ------------------------------
    let mut score_windows = 0;
    let mut score_linux = 0;
    let mut score_macos = 0;
    let mut score_bsd = 0;
    let mut score_network = 0;

    // 445 alone is NOT strong evidence of Windows.
    // macOS, NAS devices, routers, Linux Samba all expose 445.
    if open_ports.contains(&3389) || open_ports.contains(&135) {
        score_windows += 50; // strong Windows signals
    } else if open_ports.contains(&445) {
        score_windows += 10; // weak evidence only
    }

    if open_ports.contains(&22) || open_ports.contains(&111) || open_ports.contains(&631) {
        score_linux += 30;
    }

    if open_ports.contains(&548) {
        score_macos += 50;
    }

    if open_ports.contains(&23) || open_ports.contains(&161) {
        score_network += 40;
    }

    if open_ports.contains(&5353) {
        score_macos += 40;
    }

    if open_ports.contains(&631) {
        score_macos += 20;
    }
    if open_ports.contains(&445) == false
        && open_ports.contains(&22) == false
        && open_ports.contains(&631) == false
        && ports.iter().any(|p| p.window_size == Some(29200))
    {
        score_network += 40;
    }

    // ------------------------------
    // 3. SSH heuristics
    // ------------------------------
    let mut ssh_evidence = String::new();

    for fp in service_fps {
        if fp.protocol != "ssh" {
            continue;
        }

        if let Some(evidence) = &fp.evidence {
            let b = evidence.to_lowercase();
            ssh_evidence.push_str(&format!("ssh_banner: {}\n", evidence.replace('\n', " ")));

            if b.contains("ubuntu")
                || b.contains("debian")
                || b.contains("centos")
                || b.contains("fedora")
                || b.contains("alpine")
                || b.contains("arch")
            {
                score_linux += 60;
            }

            if b.contains("freebsd") || b.contains("openbsd") || b.contains("netbsd") {
                score_bsd += 70;
            }

            if b.contains("openssh_for_windows") || b.contains("winssh") || b.contains("powershell")
            {
                score_windows += 80;
                score_linux -= 20;
                score_macos -= 20;
            }

            if b.contains("darwin") || b.contains("apple") {
                score_macos += 60;
                score_windows -= 40;
            }
        }
    }

    // ------------------------------
    // 4. SMB heuristics
    // ------------------------------
    let mut smb_evidence = String::new();

    for fp in service_fps {
        if fp.protocol != "smb" {
            continue;
        }

        if let Some(ev) = &fp.evidence {
            let e = ev.to_lowercase();
            smb_evidence.push_str(&format!("smb: {}\n", ev.replace('\n', " ")));

            if e.contains("multi_channel") || e.contains("persistent_handles") {
                score_windows += 40;
            }

            if e.contains("anonymous_not_allowed") {
                score_windows += 30;
            }

            if e.contains("multi_channel") {
                score_windows += 40;
            } else {
                score_macos += 20;
            }
        }
    }

    // ------------------------------
    // 5. HTTP heuristics
    // ------------------------------
    let mut http_evidence = String::new();

    for fp in service_fps {
        if fp.protocol != "http" && fp.protocol != "https" {
            continue;
        }

        if let Some(ev) = &fp.evidence {
            let e = ev.to_lowercase();
            http_evidence.push_str(&format!("http: {}\n", ev.replace('\n', " ")));

            if e.contains("microsoft-iis") {
                score_windows += 80;
            }

            if e.contains("win64") || e.contains("win32") {
                score_windows += 40;
            }

            if e.contains("(unix)") {
                score_linux += 30;
            }

            if e.contains("nginx") {
                score_linux += 20;
            }

            if e.contains("caddy") {
                score_linux += 15;
            }

            if e.contains("darwin") || e.contains("apple") {
                score_macos += 40;
                score_windows -= 20;
            }

            if e.contains("let's encrypt") {
                score_linux += 10;
            }
        }
    }
    // ------------------------------
    // TCP/IP heuristics (read-only)
    // ------------------------------
    let mut tcp_evidence = String::new();

    for p in &ports_mut {
        if p.state != "open" && p.state != "closed" {
            continue;
        }
        // TTL
        if let Some(ttl) = p.ttl {
            let ttl = normalize_ttl(ttl);

            tcp_evidence.push_str(&format!("ttl: {}\n", ttl));

            match ttl {
                128..=255 => score_windows += 40, // Windows default TTL 128
                64 => {
                    score_linux += 20;
                    score_bsd += 20;
                    score_macos += 20;
                    score_network += 10; // routers often TTL=64
                }
                255 => score_network += 40,
                _ => {}
            }
        }

        // Window size
        if let Some(ws) = p.window_size {
            let ws = normalize_window(ws);
            tcp_evidence.push_str(&format!("window: {}\n", ws));
            if ws == 65535 {
                score_macos += 20;
            }
            match ws {
                65535 => {
                    score_windows += 20;
                    score_bsd += 20;
                }
                29200 => {
                    score_linux += 20;
                    score_network += 10;
                } // FritzBox, Linux routers
                8192 | 64240 => score_windows += 20,
                _ => {}
            }
        }

        // MSS
        if let Some(mss) = p.mss {
            let mss = normalize_mss(mss);
            tcp_evidence.push_str(&format!("mss: {}\n", mss));

            match mss {
                1460 => {
                    score_linux += 10;
                    score_macos += 10;
                    score_network += 10;
                }
                1440 => score_windows += 20,
                _ if mss <= 536 => score_network += 30,
                _ => {}
            }
        }

        // DF flag
        if let Some(df) = p.df {
            tcp_evidence.push_str(&format!("df: {}\n", df));

            if !df {
                score_network += 20; // routers often clear DF
            }
        }
        // ------------------------------

        if let Some(ts) = p.ts {
            tcp_evidence.push_str(&format!("ts: {}\n", ts));
            if ts {
                score_linux += 15;
                score_macos += 10;
                score_windows += 10;
            } else {
                score_network += 10; // routers often omit TS
            }
        }

        if let Some(ws) = p.ws {
            tcp_evidence.push_str(&format!("ws: {}\n", ws));
            match ws {
                7 => score_linux += 20,   // Linux default
                3 => score_macos += 20,   // macOS default
                8 => score_windows += 20, // Windows default
                _ => score_network += 5,
            }
        }

        if let Some(sack) = p.sackok {
            tcp_evidence.push_str(&format!("sackok: {}\n", sack));
            if sack {
                score_linux += 10;
                score_macos += 10;
                score_windows += 10;
            } else {
                score_network += 10;
            }
        }

        if let Some(ecn) = p.ecn {
            tcp_evidence.push_str(&format!("ecn: {}\n", ecn));
            if ecn {
                score_linux += 10; // Linux enables ECN more often
            }
        }
    }

    // Router / embedded Linux signature
    let is_router_like = ports_mut.iter().any(|p| p.window_size.map(normalize_window) == Some(29200))
        && !open_ports.contains(&22) // no SSH
        && !open_ports.contains(&631) // no CUPS
        && open_ports.contains(&80)
        && open_ports.contains(&443)
        && open_ports.contains(&445);

    if is_router_like {
        score_network += 80;
        score_linux -= 40;
        score_macos -= 40;
        score_windows -= 40;
    }

    // ------------------------------
    // 6. Synthesis layer
    // ------------------------------

    // Clamp negatives
    fn clamp_non_negative(v: &mut i32) {
        if *v < 0 {
            *v = 0;
        }
    }

    let mut score_windows = score_windows as i32;
    let mut score_linux = score_linux as i32;
    let mut score_macos = score_macos as i32;
    let mut score_bsd = score_bsd as i32;
    let mut score_network = score_network as i32;

    clamp_non_negative(&mut score_windows);
    clamp_non_negative(&mut score_linux);
    clamp_non_negative(&mut score_macos);
    clamp_non_negative(&mut score_bsd);
    clamp_non_negative(&mut score_network);

    // Conflict dampening
    let mut scores = vec![
        ("windows", score_windows),
        ("linux", score_linux),
        ("macos", score_macos),
        ("bsd", score_bsd),
        ("network_device", score_network),
    ];

    let max1 = scores
        .iter()
        .max_by_key(|(_, s)| *s)
        .map(|(_, s)| *s)
        .unwrap_or(0);
    let max2 = scores
        .iter()
        .filter(|(_, s)| *s != max1)
        .max_by_key(|(_, s)| *s)
        .map(|(_, s)| *s)
        .unwrap_or(0);

    if max1 > 0 && max2 > max1 / 2 {
        score_windows /= 2;
        score_linux /= 2;
        score_macos /= 2;
        score_bsd /= 2;
        score_network /= 2;
    }

    // Rebuild scores after dampening
    scores = vec![
        ("windows", score_windows),
        ("linux", score_linux),
        ("macos", score_macos),
        ("bsd", score_bsd),
        ("network_device", score_network),
    ];

    scores.sort_by(|a, b| b.1.cmp(&a.1));
    let (best_os, best_score_i32) = scores[0];

    if best_score_i32 <= 0 {
        return None;
    }

    // Confidence shaping: simple clamp for now
    // Confidence shaping: simple clamp for now
    let best_score = best_score_i32.min(100).max(10) as u8;

    // ------------------------------
    // 6b. Final OS decision
    // ------------------------------
    let mut final_os = best_os;
    let mut final_confidence = best_score;

    // If SYN/ACK+RST fingerprint is strong enough, trust it over heuristics.
    // This is what will cleanly separate your router (embedded_linux)
    // from macOS, without giving insane 100% confidence on weak matches.
    if synrst_best_score >= 60 {
        if let Some(os_name) = synrst_best_os {
            final_os = os_name;
            final_confidence = synrst_best_score.min(100) as u8;
        }
    }

    let nat_suspect = if let Some(syn_os) = synrst_best_os {
        syn_os != best_os
    } else {
        false
    };
    // ------------------------------
    // Firewall / SYN proxy detection
    // ------------------------------
    let mut firewall_suspect = false;
    let mut firewall_reason = String::new();

    // 1. SYN cookies: no TS, no WS, no SACK, MSS <= 536
    if let Some(s) = &syn_fp {
        let no_options = s.ts == Some(false) && s.ws.is_none() && s.sackok == Some(false);

        if no_options && s.mss.unwrap_or(1460) <= 536 {
            firewall_suspect = true;
            firewall_reason.push_str("syn_cookies_detected; ");
        }
    }

    // 2. SYN proxy: SYN fingerprint OS != heuristic OS
    if let Some(syn_os) = synrst_best_os {
        if syn_os != final_os {
            firewall_suspect = true;
            firewall_reason.push_str("syn_proxy_mismatch; ");
        }
    }

    // 3. SYN TTL != RST TTL (proxy or middlebox)
    if let (Some(syn), Some(rst)) = (syn_fp.as_ref(), rst_fp.as_ref()) {
        if let (Some(t1), Some(t2)) = (syn.ttl, rst.ttl) {
            if normalize_ttl(t1) != normalize_ttl(t2) {
                firewall_suspect = true;
                firewall_reason.push_str("ttl_inconsistency; ");
            }
        }
    }

    // 4. SYN window extremely small (firewall SYN/ACK)
    if let Some(s) = &syn_fp {
        if let Some(w) = s.window {
            if w < 2048 {
                firewall_suspect = true;
                firewall_reason.push_str("tiny_syn_window; ");
            }
        }
    }

    let mut synproxy_suspect = false;
    let mut synproxy_reason = String::new();

    let mut syn_time: Option<u128> = None;
    let mut rst_time: Option<u128> = None;

    // Extract timing from evidence
    for fp in service_fps {
        if fp.protocol == "tcp_syn" {
            if let Some(ev) = &fp.evidence {
                for line in ev.lines() {
                    if let Some(v) = line.strip_prefix("tcp_syn_time: ") {
                        syn_time = v.trim().parse::<u128>().ok();
                    }
                }
            }
        }
        if fp.protocol == "tcp" {
            if let Some(ev) = &fp.evidence {
                for line in ev.lines() {
                    if let Some(v) = line.strip_prefix("tcp_rst_time: ") {
                        rst_time = v.trim().parse::<u128>().ok();
                    }
                }
            }
        }
    }
    let mut rst_times: Vec<u128> = Vec::new();

    // Extract timing from evidence
    for fp in service_fps {
        if fp.protocol == "tcp_rst" {
            if let Some(ev) = &fp.evidence {
                for line in ev.lines() {
                    if let Some(v) = line.strip_prefix("tcp_rst_time: ") {
                        if let Ok(t) = v.trim().parse::<u128>() {
                            rst_times.push(t);
                        }
                    }
                }
            }
        }
    }

    // Timing analysis
    if let (Some(st), Some(rt)) = (syn_time, rst_time) {
        let delta = rt.saturating_sub(st);

        if st < 1000 && delta > 20_000 {
            synproxy_suspect = true;
            synproxy_reason.push_str("fast_synack_slow_rst; ");
        }

        if delta > 50_000 {
            synproxy_suspect = true;
            synproxy_reason.push_str("large_syn_rst_gap; ");
        }
    }
    let mut lb_suspect = false;
    let mut lb_reason = String::new();

    if rst_times.len() >= 3 {
        // basic stats
        let n = rst_times.len() as f64;
        let mean = rst_times.iter().map(|&t| t as f64).sum::<f64>() / n;

        let var = rst_times
            .iter()
            .map(|&t| {
                let dt = t as f64 - mean;
                dt * dt
            })
            .sum::<f64>()
            / n;

        let stddev = var.sqrt();

        // Heuristic: high jitter relative to mean → likely multiple backends
        // e.g. mean > 20ms and stddev > 0.5 * mean
        if mean > 20_000.0 && stddev > 0.5 * mean {
            lb_suspect = true;
            lb_reason.push_str(&format!(
                "rst_jitter_high; mean_us={:.0}, stddev_us={:.0}; ",
                mean, stddev
            ));
        }
    }
    let mut lb_family: Option<&'static str> = None;

    if lb_suspect {
        // Compute mean/stddev again (you already have them)
        let n = rst_times.len() as f64;
        let mean = rst_times.iter().map(|&t| t as f64).sum::<f64>() / n;
        let var = rst_times
            .iter()
            .map(|&t| {
                let dt = t as f64 - mean;
                dt * dt
            })
            .sum::<f64>()
            / n;
        let stddev = var.sqrt();

        // Extract TTLs from RST evidence
        let mut rst_ttls = Vec::new();
        for fp in service_fps {
            if fp.protocol == "tcp_rst" {
                if let Some(ev) = &fp.evidence {
                    for line in ev.lines() {
                        if let Some(v) = line.strip_prefix("tcp_rst_ttl: ") {
                            if let Ok(t) = v.trim().parse::<u8>() {
                                rst_ttls.push(t);
                            }
                        }
                    }
                }
            }
        }

        let ttl_uniform = rst_ttls.iter().all(|&t| t == rst_ttls[0]);
        let ttl = rst_ttls.get(0).copied().unwrap_or(64);

        // -------------------------
        // Cloudflare
        // -------------------------
        if ttl == 255 && stddev > 0.5 * mean && mean > 100_000.0 {
            lb_family = Some("cloudflare");
        }
        // -------------------------
        // AWS ELB / ALB
        // -------------------------
        else if ttl == 60 || ttl == 64 {
            if stddev < 0.2 * mean && mean >= 30_000.0 && mean <= 90_000.0 {
                lb_family = Some("aws_elb");
            }
        }
        // -------------------------
        // HAProxy
        // -------------------------
        else if ttl_uniform && stddev < 0.1 * mean && mean < 20_000.0 {
            lb_family = Some("haproxy");
        }
        // -------------------------
        // nginx load balancer
        // -------------------------
        else if ttl_uniform && stddev > 0.1 * mean && stddev < 0.5 * mean {
            lb_family = Some("nginx_lb");
        }
    }
    let mut cdn_suspect = false;
    let mut cdn_reason = String::new();

    // 1) HTTP headers / banners
    for fp in service_fps {
        if fp.protocol != "http" && fp.protocol != "https" {
            continue;
        }
        if let Some(ev) = &fp.evidence {
            let e = ev.to_lowercase();

            if e.contains("cloudflare") || e.contains("cf-ray") || e.contains("cf-cache-status") {
                cdn_suspect = true;
                cdn_reason.push_str("cloudflare_headers; ");
            }
            if e.contains("akamai") || e.contains("akamai-ghost") {
                cdn_suspect = true;
                cdn_reason.push_str("akamai_headers; ");
            }
            if e.contains("fastly") || e.contains("via: 1.1 varnish") {
                cdn_suspect = true;
                cdn_reason.push_str("fastly_headers; ");
            }
            if e.contains("cloudfront") || e.contains("x-amz-cf-id") {
                cdn_suspect = true;
                cdn_reason.push_str("cloudfront_headers; ");
            }
        }
    }

    // 2) Port pattern: 80/443 only, no SSH/SMB/etc → very CDN-like
    let only_web_ports = open_ports.iter().all(|p| *p == 80 || *p == 443);
    if only_web_ports && lb_suspect {
        cdn_suspect = true;
        cdn_reason.push_str("only_web_ports_with_lb; ");
    }

    // 3) TTL + jitter: high TTL + high jitter → edge/CDN-ish
    if lb_suspect {
        // reuse rst_times / mean / stddev if you want, or recompute quickly:
        if rst_times.len() >= 3 {
            let n = rst_times.len() as f64;
            let mean = rst_times.iter().map(|&t| t as f64).sum::<f64>() / n;
            let var = rst_times
                .iter()
                .map(|&t| {
                    let dt = t as f64 - mean;
                    dt * dt
                })
                .sum::<f64>()
                / n;
            let stddev = var.sqrt();

            // collect RST TTLs
            let mut rst_ttls = Vec::new();
            for fp in service_fps {
                if fp.protocol == "tcp_rst" {
                    if let Some(ev) = &fp.evidence {
                        for line in ev.lines() {
                            if let Some(v) = line.strip_prefix("tcp_rst_ttl: ") {
                                if let Ok(t) = v.trim().parse::<u8>() {
                                    rst_ttls.push(t);
                                }
                            }
                        }
                    }
                }
            }
            let ttl = rst_ttls.get(0).copied().unwrap_or(64);

            if ttl >= 200 && stddev > 0.5 * mean && mean > 80_000.0 {
                cdn_suspect = true;
                cdn_reason.push_str("edge_like_ttl_and_jitter; ");
            }
        }
    }
    let mut cdn_family: Option<&'static str> = None;

    // 1) Header-based detection
    for fp in service_fps {
        if fp.protocol == "http" || fp.protocol == "https" {
            if let Some(ev) = &fp.evidence {
                let e = ev.to_lowercase();

                if e.contains("cloudflare") || e.contains("cf-ray") {
                    cdn_family = Some("cloudflare_edge");
                }
                if e.contains("sucuri") || e.contains("cloudproxy") {
                    cdn_family = Some("sucuri_cloudproxy");
                }
                if e.contains("akamai") || e.contains("akamai-ghost") {
                    cdn_family = Some("akamai_edge");
                }
                if e.contains("fastly") || e.contains("varnish") {
                    cdn_family = Some("fastly_edge");
                }
                if e.contains("cloudfront") || e.contains("x-amz-cf-id") {
                    cdn_family = Some("aws_cloudfront_edge");
                }
            }
        }

        // TLS-based detection
        if fp.protocol == "tls" {
            if let Some(ev) = &fp.evidence {
                let e = ev.to_lowercase();

                if e.contains("cloudflare") {
                    cdn_family = Some("cloudflare_edge");
                }
                if e.contains("sucuri") {
                    cdn_family = Some("sucuri_cloudproxy");
                }
                if e.contains("akamai") {
                    cdn_family = Some("akamai_edge");
                }
                if e.contains("fastly") {
                    cdn_family = Some("fastly_edge");
                }
                if e.contains("cloudfront") {
                    cdn_family = Some("aws_cloudfront_edge");
                }
            }
        }
    }

    // 2) TTL-based detection
    if cdn_family.is_none() {
        if let Some(syn) = &syn_fp {
            if let Some(ttl) = syn.ttl {
                let ttl = normalize_ttl(ttl);

                if ttl == 255 {
                    cdn_family = Some("cdn_edge_high_ttl");
                }
            }
        }
    }

    // 3) SYN/RST mismatch + only web ports → reverse proxy
    let only_web = open_ports.iter().all(|p| *p == 80 || *p == 443);
    if cdn_family.is_none() && only_web && firewall_suspect {
        cdn_family = Some("generic_reverse_proxy");
    }

    // 4) SYN fingerprint OS != banner OS → WAF
    if cdn_family.is_none() && firewall_suspect {
        cdn_family = Some("generic_waf");
    }
    // JA3S-based CDN/WAF detection
    let mut ja3s_family: Option<&'static str> = None;

    for fp in service_fps {
        if fp.protocol == "tls" {
            if let Some(ev) = &fp.evidence {
                for line in ev.lines() {
                    if let Some(hash) = line.strip_prefix("tls_ja3s_like: ") {
                        let h = hash.trim();

                        // Cloudflare
                        if h == "5d5c1a0e3e0e3c3e3e3e3e3e3e3e3e3"
                            || h == "e81dd19155b0df11ef4116a85f6e4233"
                        {
                            ja3s_family = Some("cloudflare_edge");
                        }

                        // Sucuri / CloudProxy
                        if h == "e81dd19155b0df11ef4116a85f6e4233" {
                            ja3s_family = Some("sucuri_cloudproxy");
                        }

                        // Akamai
                        if h == "d4e5f1c8c7b1e6d2f3a4b5c6d7e8f9a0" {
                            ja3s_family = Some("akamai_edge");
                        }

                        // Fastly
                        if h == "3a3c1f1e2d2c3b3a4a4b5c5d6e6f7071" {
                            ja3s_family = Some("fastly_edge");
                        }

                        // AWS CloudFront
                        if h == "b2c1d3e4f5a697887766554433221100" {
                            ja3s_family = Some("aws_cloudfront_edge");
                        }
                    }
                }
            }
        }
    }
    // Prefer JA3S classification over header-based if both exist
    let final_cdn_family = ja3s_family.or(cdn_family);
    let tls_stack = classify_tls_stack_from_evidence(service_fps);

    // ------------------------------
    // 7. Build evidence string
    // ------------------------------
    let mut evidence = String::new();
    evidence.push_str(&format!("os_guess: {}\n", final_os));
    evidence.push_str(&format!("confidence: {}\n", final_confidence));
    evidence.push_str(&format!("open_ports: {:?}\n", open_ports));

    if let Some(os) = synrst_best_os {
        evidence.push_str(&format!("syn_fp_os: {}\n", os));
        evidence.push_str(&format!("syn_fp_score: {}\n", synrst_best_score));
    }

    if !ssh_evidence.is_empty() {
        evidence.push_str(&ssh_evidence);
    }
    if !smb_evidence.is_empty() {
        evidence.push_str(&smb_evidence);
    }
    if !http_evidence.is_empty() {
        evidence.push_str(&http_evidence);
    }
    if !tcp_evidence.is_empty() {
        evidence.push_str(&tcp_evidence);
    }
    if let Some(os) = synrst_best_os {
        evidence.push_str(&format!("syn_fp_os: {}\n", os));
        evidence.push_str(&format!("syn_fp_score: {}\n", synrst_best_score));
    }
    if firewall_suspect {
        evidence.push_str(&format!("firewall_suspect: true\n"));
        evidence.push_str(&format!("firewall_reason: {}\n", firewall_reason));
    }
    if synproxy_suspect {
        evidence.push_str("synproxy_suspect: true\n");
        evidence.push_str(&format!("synproxy_reason: {}\n", synproxy_reason));
    }
    if lb_suspect {
        evidence.push_str("load_balancer_suspect: true\n");
        evidence.push_str(&format!("load_balancer_reason: {}\n", lb_reason));
    }
    if let Some(fam) = lb_family {
        evidence.push_str(&format!("load_balancer_family: {}\n", fam));
    }
    if cdn_suspect {
        evidence.push_str("cdn_edge_suspect: true\n");
        evidence.push_str(&format!("cdn_edge_reason: {}\n", cdn_reason));
    }
    if let Some(cf) = cdn_family {
        evidence.push_str(&format!("cdn_family: {}\n", cf));
    }
    if let Some(cf) = final_cdn_family {
        evidence.push_str(&format!("cdn_family: {}\n", cf));
    }
    match tls_stack {
        TlsStack::OpenSsl => evidence.push_str("tls_stack: openssl\n"),
        TlsStack::BoringSsl => evidence.push_str("tls_stack: boringssl\n"),
        TlsStack::GoTls => evidence.push_str("tls_stack: go_tls\n"),
        TlsStack::Nss => evidence.push_str("tls_stack: nss\n"),
        TlsStack::Java => evidence.push_str("tls_stack: java_tls\n"),
        TlsStack::Rustls => evidence.push_str("tls_stack: rustls\n"),
        TlsStack::Unknown => {}
    }

    // ------------------------------
    // 8. Build synthetic fingerprint
    // ------------------------------
    let mut fp = ServiceFingerprint::from_banner(ip, 0, "os", evidence);
    fp.confidence = final_confidence;

    if let Some(ev) = &fp.evidence {
        if let Some(line) = ev.lines().find(|l| l.starts_with("tcp_syn_vendor: ")) {
            let vendor = line
                .trim_start_matches("tcp_syn_vendor: ")
                .trim()
                .to_lowercase();
            if vendor.contains("apple") {
                score_macos += 50;
            } else if vendor.contains("avm") {
                score_network += 80;
            } else if vendor.contains("intel") || vendor.contains("realtek") {
                score_linux += 20;
            } else if vendor.contains("microsoft") {
                score_windows += 50;
            } else if vendor.contains("ubiquiti") {
                score_network += 80;
            } else if vendor.contains("synology") || vendor.contains("qnap") {
                score_network += 60;
            }
        }
    }
    if fp.protocol == "tls" {
        if let Some(ev) = &fp.evidence {
            for line in ev.lines() {
                if let Some(v) = line.strip_prefix("tls_ja3s_like: ") {
                    let h = v.trim();

                    // Example heuristics — tune after collecting real data
                    if ev.contains("nginx") {
                        score_linux += 20;
                    }
                    if ev.contains("Microsoft") || ev.contains("IIS") {
                        score_windows += 40;
                    }
                    if ev.contains("Apple") || ev.contains("Darwin") {
                        score_macos += 30;
                    }
                }
            }
        }
    }

    // NAT detection (optional ICMP TTL: pass None for now)
    let is_nat = detect_nat(
        synrst_best_os.as_deref(),
        final_os,
        &syn_fp,
        None, // you can add ICMP TTL later
    );

    if is_nat {
        fp.service = Some(format!("{} (behind NAT)", final_os));
    }

    fp.confidence = final_confidence;

    Some(fp)
}

pub fn apply_tcp_syn_to_ports(ports: &mut [PortResult], fps: &[ServiceFingerprint]) {
    for fp in fps.iter().filter(|f| f.protocol == "tcp_syn") {
        let port = fp.port;

        if let Some(pr) = ports
            .iter_mut()
            .find(|p| p.protocol == "tcp" && p.port == port)
        {
            if let Some(ev) = &fp.evidence {
                for line in ev.lines() {
                    if let Some(v) = line.strip_prefix("tcp_syn_ttl: ") {
                        pr.ttl = v.trim().parse().ok();
                    } else if let Some(v) = line.strip_prefix("tcp_syn_window: ") {
                        pr.window_size = v.trim().parse().ok();
                    } else if let Some(v) = line.strip_prefix("tcp_syn_mss: ") {
                        pr.mss = v.trim().parse().ok();
                    } else if let Some(v) = line.strip_prefix("tcp_syn_df: ") {
                        pr.df = v.trim().parse().ok();
                    } else if let Some(v) = line.strip_prefix("tcp_syn_ts: ") {
                        pr.ts = Some(v.trim() == "true");
                    } else if let Some(v) = line.strip_prefix("tcp_syn_ws: ") {
                        let ws_val: u8 = v.trim().parse().unwrap_or(0);
                        // Treat 0 as "no WS option"
                        if ws_val == 0 {
                            pr.ws = None;
                        } else {
                            pr.ws = Some(ws_val);
                        }
                    } else if let Some(v) = line.strip_prefix("tcp_syn_sackok: ") {
                        pr.sackok = Some(v.trim() == "true");
                    } else if let Some(v) = line.strip_prefix("tcp_syn_ecn: ") {
                        pr.ecn = Some(v.trim() == "true");
                    }
                }
            }
        }
    }
}

fn normalize_ttl(observed: u8) -> u8 {
    match observed {
        0..=64 => 64,
        65..=128 => 128,
        _ => 255,
    }
}

fn normalize_window(w: u32) -> u32 {
    match w {
        28000..=31000 => 29200,
        64000..=66000 => 65535,
        8192 => 8192,
        _ => w,
    }
}

fn normalize_mss(m: u16) -> u16 {
    match m {
        1440..=1460 => 1460,
        _ => m,
    }
}

fn score_syn(obs: &SynAckFp, fp: &OsSynFp) -> i32 {
    let mut s = 0;

    // TTL
    if let Some(ttl) = obs.ttl {
        if normalize_ttl(ttl) == fp.ttl {
            s += 20;
        }
    }

    // Window
    if let Some(w) = obs.window {
        if normalize_window(w) == fp.window {
            s += 30;
        }
    }

    // MSS
    if obs.mss == fp.mss {
        s += 10;
    }

    // DF
    if obs.df == Some(fp.df) {
        s += 5;
    }

    // TS
    if obs.ts == fp.ts {
        s += 15;
    }

    // WS
    if obs.ws == fp.ws {
        s += 15;
    }

    // SACKOK
    if obs.sackok == fp.sackok {
        s += 10;
    }

    // ECN
    if obs.ecn == fp.ecn {
        s += 5;
    }

    s
}

fn score_rst(obs: &RstFp, fp: &OsRstFp) -> i32 {
    let mut s = 0;

    // TTL
    if let Some(ttl) = obs.ttl {
        if normalize_ttl(ttl) == fp.ttl {
            s += 10;
        }
    }

    // Window
    if let Some(w) = obs.window {
        if normalize_window(w) == fp.window {
            s += 20;
        }
    }

    // DF
    if obs.df == Some(fp.df) {
        s += 5;
    }

    s
}

fn os_fingerprint_table() -> Vec<OsFingerprint> {
    vec![
        // -------------------------
        // Linux (generic servers)
        // -------------------------
        OsFingerprint {
            name: "linux",
            syn: OsSynFp {
                ttl: 64,
                window: 29200,
                mss: Some(1460),
                df: true,
                ts: Some(true),
                ws: Some(7),
                sackok: Some(true),
                ecn: Some(true),
            },
            rst: OsRstFp {
                ttl: 64,
                window: 0,
                df: true,
            },
        },
        // -------------------------
        // Windows 10/11
        // -------------------------
        OsFingerprint {
            name: "windows",
            syn: OsSynFp {
                ttl: 128,
                window: 64240,
                mss: Some(1460),
                df: true,
                ts: Some(true),
                ws: Some(8),
                sackok: Some(true),
                ecn: Some(false),
            },
            rst: OsRstFp {
                ttl: 128,
                window: 8192,
                df: true,
            },
        },
        // -------------------------
        // macOS (tolerant to LAN behavior)
        // -------------------------
        OsFingerprint {
            name: "macos",
            syn: OsSynFp {
                ttl: 64,
                window: 65535,
                mss: Some(1460),
                df: true,

                // On LAN, macOS often has TS disabled.
                ts: Some(false),

                // WS is not reliable in your captures → don't care.
                ws: None,

                // SACKOK also not reliably visible → don't care.
                sackok: None,

                ecn: Some(false),
            },
            rst: OsRstFp {
                ttl: 64,
                window: 65535,
                df: true,
            },
        },
        // -------------------------
        // BSD (FreeBSD/OpenBSD/NetBSD)
        // -------------------------
        OsFingerprint {
            name: "bsd",
            syn: OsSynFp {
                ttl: 64,
                window: 65535,
                mss: Some(1460),
                df: true,
                ts: Some(true),
                ws: Some(6),
                sackok: Some(true),
                ecn: Some(false),
            },
            rst: OsRstFp {
                ttl: 64,
                window: 65535,
                df: true,
            },
        },
        // -------------------------
        // Embedded Linux / Routers
        // FritzBox, OpenWRT, ISP boxes
        // -------------------------
        OsFingerprint {
            name: "embedded_linux",
            syn: OsSynFp {
                ttl: 64,
                window: 29200,
                mss: Some(1460),
                df: true,
                ts: Some(false),
                ws: None,
                sackok: Some(false),
                ecn: Some(false),
            },
            rst: OsRstFp {
                ttl: 64,
                window: 0,
                df: true,
            },
        },
    ]
}

fn detect_nat(
    syn_os: Option<&str>,
    heuristic_os: &str,
    syn_fp: &Option<SynAckFp>,
    icmp_ttl: Option<u8>,
) -> bool {
    let mut nat_score = 0;

    // 1. SYN OS != heuristic OS
    if let Some(syn) = syn_os {
        if syn != heuristic_os {
            nat_score += 50;
        }
    }

    // 2. SYN TTL != ICMP TTL
    if let (Some(syn), Some(icmp)) = (syn_fp.as_ref().and_then(|s| s.ttl), icmp_ttl) {
        if normalize_ttl(syn) != normalize_ttl(icmp) {
            nat_score += 50;
        }
    }

    // 3. macOS banners but Linux/Router SYN
    if heuristic_os == "macos" {
        if let Some(s) = syn_fp {
            if normalize_window(s.window.unwrap_or(0)) == 29200 {
                nat_score += 40;
            }
        }
    }

    // 4. macOS banners but TS/SACK/WS all missing
    if heuristic_os == "macos" {
        if let Some(s) = syn_fp {
            if s.ts == Some(false) && s.ws.is_none() && s.sackok == Some(false) {
                nat_score += 30;
            }
        }
    }

    nat_score >= 60
}

fn classify_tls_stack_from_evidence(service_fps: &[ServiceFingerprint]) -> TlsStack {
    let mut stack = TlsStack::Unknown;

    for fp in service_fps {
        if fp.protocol != "tls" {
            continue;
        }
        let Some(ev) = &fp.evidence else { continue };

        let mut ja3s: Option<String> = None;
        let mut neg: Option<String> = None;

        for line in ev.lines() {
            if let Some(v) = line.strip_prefix("tls_ja3s_like: ") {
                ja3s = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("tls_negotiation: ") {
                neg = Some(v.trim().to_string());
            }
        }

        let ja3s = ja3s.as_deref().unwrap_or("");
        let neg = neg.as_deref().unwrap_or("");

        // --- JA3S-based hints (fill with real hashes from your corpus) ---

        // Typical Go TLS server fingerprints
        if matches!(
            ja3s,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" | "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ) {
            stack = TlsStack::GoTls;
        }

        // Typical BoringSSL (Google / Cloudflare / gRPC)
        if matches!(
            ja3s,
            "cccccccccccccccccccccccccccccccc" | "dddddddddddddddddddddddddddddddd"
        ) {
            stack = TlsStack::BoringSsl;
        }

        // Typical OpenSSL
        if matches!(
            ja3s,
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" | "ffffffffffffffffffffffffffffffff"
        ) {
            stack = TlsStack::OpenSsl;
        }

        // Typical NSS (Firefox, some CDNs)
        if matches!(
            ja3s,
            "11111111111111111111111111111111" | "22222222222222222222222222222222"
        ) {
            stack = TlsStack::Nss;
        }

        // Typical Java TLS
        if matches!(
            ja3s,
            "99999999999999999999999999999999" | "88888888888888888888888888888888"
        ) {
            stack = TlsStack::Java;
        }

        // --- Fallback heuristics on negotiation string ---

        // Go TLS often has no ALPN + specific cipher ordering; you can refine this later.
        if stack == TlsStack::Unknown
            && neg.contains("ver=TLSv1.3;cipher=TLS_AES_128_GCM_SHA256")
            && !neg.contains("alpn=h2")
        {
            stack = TlsStack::GoTls;
        }

        // BoringSSL: very ALPN‑heavy, HTTP/2 first, modern ciphers only.
        if stack == TlsStack::Unknown
            && neg.contains("alpn=h2")
            && neg.contains("TLS_AES_256_GCM_SHA384")
        {
            stack = TlsStack::BoringSsl;
        }

        // OpenSSL: often exposes older ciphers on non‑CDN hosts; again, refine with real data.
        if stack == TlsStack::Unknown && neg.contains("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384") {
            stack = TlsStack::OpenSsl;
        }

        // Java: tends to have odd cipher naming / ordering; placeholder for now.
        if stack == TlsStack::Unknown
            && neg.contains("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
            && neg.contains("alpn=") == false
        {
            stack = TlsStack::Java;
        }
    }

    stack
}
