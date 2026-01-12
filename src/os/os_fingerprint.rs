use crate::service::ServiceFingerprint;
use crate::types::PortResult;

pub struct OsGuess {
    pub os: &'static str,
    pub confidence: u8,
    pub evidence: String,
}

pub fn infer_os_from_ports(ip: &str, ports: &[PortResult]) -> Option<ServiceFingerprint> {
    let open_ports: Vec<u16> = ports
        .iter()
        .filter(|r| r.state == "open" || r.state == "open|filtered")
        .map(|r| r.port)
        .collect();

    if open_ports.is_empty() {
        return None;
    }

    let mut score_windows = 0;
    let mut score_linux = 0;
    let mut score_macos = 0;
    let mut score_network = 0;

    // Very conservative initial heuristics
    if open_ports.contains(&445) || open_ports.contains(&3389) || open_ports.contains(&135) {
        score_windows += 50;
    }

    if open_ports.contains(&22) || open_ports.contains(&111) || open_ports.contains(&631) {
        score_linux += 40;
    }

    if open_ports.contains(&548) {
        score_macos += 60;
    }

    if open_ports.contains(&23) || open_ports.contains(&161) {
        score_network += 40;
    }

    let mut scores = vec![
        ("windows", score_windows),
        ("linux", score_linux),
        ("macos", score_macos),
        ("network_device", score_network),
    ];

    scores.sort_by(|a, b| b.1.cmp(&a.1));
    let (best_os, best_score) = scores[0];

    if best_score == 0 {
        return None;
    }

    let mut evidence = String::new();
    evidence.push_str(&format!("os_guess: {}\n", best_os));
    evidence.push_str(&format!("confidence: {}\n", best_score));
    evidence.push_str(&format!("open_ports: {:?}\n", open_ports));

    let mut fp = ServiceFingerprint::from_banner(ip, 0, "os", evidence);
    fp.confidence = best_score.min(100) as u8;

    Some(fp)
}




pub fn infer_os_for_host(
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
    // 2. Port-pattern heuristics
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

    // ------------------------------
    // 3. SSH banner heuristics
    // ------------------------------
    let mut ssh_evidence = String::new();

    for fp in service_fps {
        if fp.protocol != "ssh" {
            continue;
        }

        if let Some(banner) = &fp.evidence {
            let b = banner.to_lowercase();
            ssh_evidence.push_str(&format!("ssh_banner: {}\n", banner.replace('\n', " ")));

            // Linux distro hints
            if b.contains("ubuntu") || b.contains("debian") || b.contains("centos")
                || b.contains("fedora") || b.contains("alpine") || b.contains("arch")
            {
                score_linux += 60;
            }

            // BSD hints
            if b.contains("freebsd") || b.contains("openbsd") || b.contains("netbsd") {
                score_bsd += 70;
            }

            // macOS hints
            if b.contains("darwin") {
                score_macos += 40;
            }

            // Windows SSH servers (rare but possible)
            if b.contains("winssh") || b.contains("powershell") {
                score_windows += 40;
            }
        }
    }

    // ------------------------------
    // 4. Combine scores
    // ------------------------------
    let mut scores = vec![
        ("windows", score_windows),
        ("linux", score_linux),
        ("macos", score_macos),
        ("bsd", score_bsd),
        ("network_device", score_network),
    ];

    scores.sort_by(|a, b| b.1.cmp(&a.1));
    let (best_os, best_score) = scores[0];

    if best_score == 0 {
        return None;
    }

    // ------------------------------
    // 5. Build evidence string
    // ------------------------------
    let mut evidence = String::new();
    evidence.push_str(&format!("os_guess: {}\n", best_os));
    evidence.push_str(&format!("confidence: {}\n", best_score));
    evidence.push_str(&format!("open_ports: {:?}\n", open_ports));

    if !ssh_evidence.is_empty() {
        evidence.push_str(&ssh_evidence);
    }

    // ------------------------------
    // 6. Build synthetic fingerprint
    // ------------------------------
    let mut fp = ServiceFingerprint::from_banner(ip, 0, "os", evidence);
    fp.confidence = best_score.min(100) as u8;

    Some(fp)
}
