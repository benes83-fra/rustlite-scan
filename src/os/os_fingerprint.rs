use crate::service::ServiceFingerprint;
use crate::types::PortResult;


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

    for p in &ports_mut {
        if p.state != "open" && p.state !="closed"{
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
            let ws  = normalize_window(ws);
            tcp_evidence.push_str(&format!("window: {}\n", ws));
            if ws == 65535 {
                score_macos += 20;
            }
            match ws {
                65535 => { score_windows += 20; score_bsd += 20; }
                29200 => { score_linux += 20; score_network += 10; } // FritzBox, Linux routers
                8192 | 64240 => score_windows += 20,
                _ => {}
            }
        }


        // MSS
         if let Some(mss) = p.mss {
            let mss = normalize_mss(mss);
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
    // Router / embedded Linux signature
    let is_router_like =
        ports_mut.iter().any(|p| p.window_size.map(normalize_window) == Some(29200))
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

    // ------------------------------
    // 8. Build synthetic fingerprint
    // ------------------------------
    let mut fp = ServiceFingerprint::from_banner(ip, 0, "os", evidence);
    fp.confidence = final_confidence;

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
