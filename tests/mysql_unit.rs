



#[cfg(test)]
mod tests {
    use rustlite_scan::probes::mysql::MysqlInfo;
    use rustlite_scan::probes::mysql::parse_handshake;

    

    #[test]
    fn parse_handshake_ok() {
        // Construct a minimal fake handshake packet
        // Protocol version = 10
        // Server version string = "8.0.39" + NUL
        // Connection ID = 1234
        // Capability flags low = 0xFFFF, high = 0x0001
        // Auth plugin name = "mysql_native_password" + NUL

        let mut buf = Vec::new();
        buf.push(10u8); // protocol version
        buf.extend_from_slice(b"8.0.39\0"); // server version string
        buf.extend_from_slice(&1234u32.to_le_bytes()); // connection id
        buf.extend_from_slice(&[0; 9]); // filler + part of auth plugin data
        buf.extend_from_slice(&0xFFFFu16.to_le_bytes()); // capability flags low
        buf.extend_from_slice(&[0; 3]); // charset + status
        buf.extend_from_slice(&0x0001u16.to_le_bytes()); // capability flags high
        buf.extend_from_slice(&[0; 11]); // skip auth plugin length + reserved
        buf.extend_from_slice(b"mysql_native_password\0"); // auth plugin name

        let info:MysqlInfo = parse_handshake(&buf).expect("handshake should parse");
        assert_eq!(info.protocol_version, 10);
        assert_eq!(info.server_version.as_deref(), Some("8.0.39"));
        assert_eq!(info.capabilities & 0xFFFF, 0xFFFF);
        assert_eq!(info.auth_plugin.as_deref(), Some("mysql_native_password"));
    }

    #[test]
    fn parse_handshake_too_short() {
        let buf = vec![10u8]; // clearly too short
        assert!(parse_handshake(&buf).is_none());
    }
}
