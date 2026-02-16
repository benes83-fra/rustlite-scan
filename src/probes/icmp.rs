use std::net::IpAddr;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// Cross-platform system ping helper with IPv6 awareness.
/// Returns true if a reply is detected.
pub async fn icmp_ping_addr(ip: IpAddr, timeout_ms: u64) -> bool {
    let ip_s = ip.to_string();

    // Build args in a Vec so we can insert the IPv6 flag when needed
    let mut args: Vec<String> = Vec::new();

    // On Windows and Unix, `-6` forces IPv6. We'll add it when ip is IPv6.
    if ip.is_ipv6() {
        args.push("-6".to_string());
    }

    #[cfg(target_os = "windows")]
    {
        args.push("-n".to_string());
        args.push("1".to_string());
        args.push("-w".to_string());
        args.push(timeout_ms.to_string());
        args.push(ip_s.clone());
    }

    #[cfg(not(target_os = "windows"))]
    {
        args.push("-c".to_string());
        args.push("1".to_string());
        // Many Unix pings expect seconds for -W; we round up
        args.push("-W".to_string());
        args.push(((timeout_ms + 999) / 1000).to_string());
        args.push(ip_s.clone());
    }

    // Build command
    let mut cmd = Command::new("ping");
    for a in &args {
        cmd.arg(a);
    }

    let fut = async {
        match cmd.output().await {
            Ok(out) => {
                if out.status.success() {
                    return true;
                }
                let s = String::from_utf8_lossy(&out.stdout).to_lowercase();
                s.contains("ttl") || s.contains("bytes from") || s.contains("time=")
            }
            Err(_) => false,
        }
    };

    match timeout(Duration::from_millis(timeout_ms + 500), fut).await {
        Ok(b) => b,
        Err(_) => false,
    }
}
