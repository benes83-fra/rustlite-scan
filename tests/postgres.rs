#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_message_length_and_protocol() {
        let msg = build_startup_message("tester");
        // first 4 bytes = length
        let len = u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize;
        assert_eq!(len, msg.len());
        // protocol at offset 4
        let proto = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
        assert_eq!(proto, 0x00030000);
        // contains user key and value
        let s = String::from_utf8_lossy(&msg);
        assert!(s.contains("user"));
        assert!(s.contains("tester"));
    }

    #[test]
    fn parse_cstring_pair_ok() {
        let mut v = Vec::new();
        v.extend_from_slice(b"server_version\013.4\0");
        let pair = parse_cstring_pair(&v).unwrap();
        assert_eq!(pair.0, "server_version");
        assert_eq!(pair.1, "13.4");
    }
}
