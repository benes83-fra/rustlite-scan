use anyhow::Result;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use std::net::{SocketAddr, ToSocketAddrs};

pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if let Some((a, b)) = part.split_once('-') {
            let start: u16 = a.parse()?;
            let end: u16 = b.parse()?;
            for p in start.min(end)..=start.max(end) {
                ports.push(p);
            }
        } else {
            ports.push(part.parse()?);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

pub fn expand_targets(target: &str) -> Result<Vec<String>> {
    if target.contains('/') {
        // Decide IPv4 vs IPv6 by presence of ':' (IPv6) or '.' (IPv4)
        if target.contains(':') {
            let cidr: Ipv6Cidr = target.parse()?;
            Ok(cidr.iter().map(|ip| ip.to_string()).collect())
        } else {
            let cidr: Ipv4Cidr = target.parse()?;
            Ok(cidr.iter().map(|ip| ip.to_string()).collect())
        }
    } else {
        let addrs = (target, 0).to_socket_addrs()?;
        let mut ips = addrs
            .filter_map(|sa| match sa {
                SocketAddr::V4(v4) => Some(v4.ip().to_string()),
                SocketAddr::V6(v6) => Some(v6.ip().to_string()),
            })
            .collect::<Vec<_>>();

        ips.sort();
        ips.dedup();

        if ips.is_empty() {
            Ok(vec![target.to_string()])
        } else {
            Ok(ips)
        }
    }
}
