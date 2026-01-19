use crate::service::ServiceFingerprint;
use crate::types::PortResult;

pub struct OsGuess {
    pub os: &'static str,
    pub confidence: u8,
    pub evidence: String,
}

pub fn infer_os(
    ip: &str,
    ports: &[PortResult],
    service_fps: &[ServiceFingerprint],
) -> Option<ServiceFingerprint> {
    // ------------------------------
    // 1. Collect open ports
    // ------------------------------
    let open_ports: Vec<u16> = ports
        .iter()
        .filter(|r| r.state == "open" || r.state == "open|filtered")
        .map(|r| r.port)
        .collect();

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

            if ttl >= 120 {
                score_windows += 40;
            } else if ttl >= 60 && ttl < 70 {
                score_linux += 20;
                score_macos += 20;
            } else if ttl >= 250 {
                score_network += 40;
            }
        }

        // Window size
        if let Some(ws) = p.window_size {
            tcp_evidence.push_str(&format!("window: {}\n", ws));

            if ws == 65535 {
                score_macos += 20;
                score_bsd += 20;
            }

            if ws == 8192 || ws == 64240 {
                score_windows += 20;
            }

            if ws >= 29200 && ws <= 65535 {
                score_linux += 10;
            }
        }

        // MSS
        if let Some(mss) = p.mss {
            tcp_evidence.push_str(&format!("mss: {}\n", mss));

            if mss == 1460 {
                score_linux += 10;
                score_macos += 10;
                score_windows += 5;
            }

            if mss == 1440 {
                score_windows += 20;
            }

            if mss <= 536 {
                score_network += 30;
            }
        }

        // DF flag
        if let Some(df) = p.df {
            tcp_evidence.push_str(&format!("df: {}\n", df));

            if !df {
                score_network += 20;
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


    // ------------------------------
    // 8. Build synthetic fingerprint
    // ------------------------------
    let mut fp = ServiceFingerprint::from_banner(ip, 0, "os", evidence);
    fp.confidence = best_score;

    Some(fp)
}
