use crate::service::ServiceFingerprint;
use crate::types::PortResult;

pub struct OsGuess {
    pub os: &'static str,
    pub confidence: u8,
    pub evidence: String,
}
use std::collections::BTreeSet;

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

    let mut open_ports: Vec<u16> = ports
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

    if open_ports.contains(&445) || open_ports.contains(&3389) || open_ports.contains(&135) {
        score_windows += 50;
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

            if b.contains("openssh_for_windows") || b.contains("winssh") || b.contains("powershell") {
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

    for p in ports {
        // TTL
        if let Some(ttl) = p.ttl {
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
            tcp_evidence.push_str(&format!("window: {}\n", ws));

            match ws {
                65535 => { score_windows += 20; score_bsd += 20; }
                29200 => { score_linux += 20; score_network += 10; } // FritzBox, Linux routers
                8192 | 64240 => score_windows += 20,
                _ => {}
            }
        }


        // MSS
         if let Some(mss) = p.mss {
            tcp_evidence.push_str(&format!("mss: {}\n", mss));

            match mss {
                1460 => { score_linux += 10; score_macos += 10; score_network += 10; }
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

    let max1 = scores.iter().max_by_key(|(_, s)| *s).map(|(_, s)| *s).unwrap_or(0);
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
    let best_score = best_score_i32.min(100).max(10) as u8;

    // ------------------------------
    // 7. Build evidence string
    // ------------------------------
    let mut evidence = String::new();
    evidence.push_str(&format!("os_guess: {}\n", best_os));
    evidence.push_str(&format!("confidence: {}\n", best_score));
    evidence.push_str(&format!("open_ports: {:?}\n", open_ports));
   
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

    //let evidence = dedupe_lines(&evidence);


    // ------------------------------
    // 8. Build synthetic fingerprint
    // ------------------------------
    let mut fp = ServiceFingerprint::from_banner(ip, 0, "os", evidence);
    fp.confidence = best_score;

    Some(fp)
}



pub fn apply_tcp_syn_to_ports(
    ports: &mut [PortResult],
    fps: &[ServiceFingerprint],
) {
    for fp in fps.iter().filter(|f| f.protocol == "tcp_syn") {
        let port = fp.port;

        if let Some(pr) = ports.iter_mut().find(|p| p.protocol == "tcp" && p.port == port) {
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
                        pr.ws = v.trim().parse().ok();
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
