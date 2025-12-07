
#[cfg(test)]
mod tests {
    use rustlite_scan::probes::snmp::SnmpProbe;
    use rustlite_scan::probes::Probe;


    // Integration test: requires a local SNMP agent on 127.0.0.1:161 (UDP).
    // Run `docker run --rm -p 161:161/udp instrumentisto/snmpd` before running tests.
    #[tokio::test]
    async fn snmp_probe_local_snmpd() {
        let probe = SnmpProbe;
        // port 161 is default; timeout 1000ms is reasonable for local container
        let fp = probe.probe("127.0.0.1", 161, 1000).await;
        assert!(fp.is_some(), "SNMP probe returned None; ensure snmpd is running on 127.0.0.1:161");
        let fp = fp.unwrap();
        let ev = fp.evidence.unwrap_or_default();
        // Expect either a sysDescr line or raw hex; at minimum evidence should be non-empty
        assert!(!ev.is_empty(), "SNMP evidence empty");
        // Optional: assert that evidence contains SNMP_sysDescr or SNMP_raw
        assert!(ev.contains("SNMP_sysDescr") || ev.contains("SNMP_raw"));
    }
}
