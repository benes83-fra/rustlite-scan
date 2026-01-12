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
