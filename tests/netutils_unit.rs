// tests/netutils_unit.rs
use rustlite_scan::netutils::{parse_ports, expand_targets};

#[test]
fn parse_ports_ranges_and_list() {
    let p = parse_ports("22,80,100-102").unwrap();
    assert!(p.contains(&22));
    assert!(p.contains(&80));
    assert!(p.contains(&100) && p.contains(&102));
}

#[test]
fn expand_single_host() {
    // If DNS resolution is available this will resolve; otherwise it should return the input
    let res = expand_targets("localhost").unwrap();
    assert!(!res.is_empty());
}
