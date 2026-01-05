use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::probes::{Probe, ProbeContext, helper::push_line};
use crate::service::ServiceFingerprint;

pub struct ModbusProbe;

#[async_trait::async_trait]
impl Probe for ModbusProbe {
    async fn probe(&self, ip: &str, port: u16, timeout_ms: u64) -> Option<ServiceFingerprint> {
        let mut evidence = String::new();
        let mut confidence: u8 = 40;
        let timeout_dur = Duration::from_millis(timeout_ms);

        // --- 1) TCP connect ---
        let addr = format!("{}:{}", ip, port);
        let mut stream = match timeout(timeout_dur, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => {
                push_line(&mut evidence, "modbus", "tcp_connect_failed");
                let mut fp = ServiceFingerprint::from_banner(ip, port, "modbus", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        // --- 2) First attempt: Function 0x11 (Report Server ID) ---
        let mut got_useful_response = false;

        if let Some((_resp, parsed_conf, maybe_vendor_conf)) =
            modbus_report_server_id(&mut stream, timeout_dur, &mut evidence).await
        {
            confidence = confidence.max(parsed_conf);
            if let Some(v_conf) = maybe_vendor_conf {
                confidence = confidence.max(v_conf);
            }
            got_useful_response = true;

            // We already have a good response; build fingerprint.
            let mut fp = ServiceFingerprint::from_banner(ip, port, "modbus", evidence);
            fp.confidence = confidence;
            return Some(fp);
        }

        // --- 3) Fallback: Function 0x03 (Read Holding Registers) ---
        // Reconnect for a clean transaction
        // --- 3) Fallback: Function 0x03 and 0x04 ---
        // Reconnect for a clean transaction for FC03
        let mut stream = match timeout(timeout_dur, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => {
                if !got_useful_response {
                    push_line(&mut evidence, "modbus", "tcp_reconnect_failed_fc03");
                }
                let mut fp = ServiceFingerprint::from_banner(ip, port, "modbus", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        if let Some(parsed_conf) =
            modbus_read_holding_registers(&mut stream, timeout_dur, &mut evidence).await
        {
            confidence = confidence.max(parsed_conf);
            got_useful_response = true;
        }

        // Reconnect again for FC04, only if we want more detail
        let mut stream = match timeout(timeout_dur, TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => s,
            _ => {
                let mut fp = ServiceFingerprint::from_banner(ip, port, "modbus", evidence);
                fp.confidence = confidence;
                return Some(fp);
            }
        };

        if let Some(parsed_conf) =
            modbus_read_input_registers(&mut stream, timeout_dur, &mut evidence).await
        {
            confidence = confidence.max(parsed_conf);
            got_useful_response = true;
        }


        // --- 4) Finalize fingerprint ---
        if !got_useful_response {
            push_line(&mut evidence, "modbus", "no_useful_response");
        }

        let mut fp = ServiceFingerprint::from_banner(ip, port, "modbus", evidence);
        fp.confidence = confidence;
        Some(fp)
    }

    async fn probe_with_ctx(
        &self,
        ip: &str,
        port: u16,
        ctx: ProbeContext,
    ) -> Option<ServiceFingerprint> {
        self.probe(
            ip,
            port,
            ctx.get("timeout_ms")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(2000),
        )
        .await
    }

    fn ports(&self) -> Vec<u16> {
        vec![502,5020]
    }

    fn name(&self) -> &'static str {
        "modbus"
    }
}

// --- Internal helpers ---

async fn modbus_report_server_id(
    stream: &mut TcpStream,
    timeout_dur: Duration,
    evidence: &mut String,
) -> Option<(Vec<u8>, u8, Option<u8>)> {
    // MBAP + PDU (Function 0x11)
    // 00 01 = Transaction ID
    // 00 00 = Protocol ID
    // 00 06 = Length
    // FF    = Unit ID
    // 11    = Function Code (Report Server ID)
    // 00 00 = Dummy data
    let request: [u8; 12] = [
        0x00, 0x01, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x06, // Length
        0xFF,       // Unit ID
        0x11,       // Function 0x11
        0x00, 0x00, // Dummy
        0x00, 0x00, // Padding
    ];

    // Send
    if timeout(timeout_dur, stream.write_all(&request))
        .await
        .is_err()
    {
        push_line(evidence, "modbus", "send_error_fc11");
        return None;
    }

    // Receive
    let mut buf = [0u8; 1024];
    let n = match timeout(timeout_dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => {
            push_line(evidence, "modbus", "no_response_fc11");
            return None;
        }
    };

    let resp = buf[..n].to_vec();
    push_line(evidence, "modbus_raw_fc11", &format!("{:02X?}", &resp));

    // Basic length check
    if resp.len() < 9 {
        push_line(evidence, "modbus", "short_response_fc11");
        return None;
    }

    let function = resp[7];

    // Exception?
    if function & 0x80 != 0 {
        let exception_code = resp[8];
        push_line(
            evidence,
            "modbus_exception_fc11",
            &format!("0x{:02X}", exception_code),
        );
        // 60 = we know it's Modbus, but exception
        return Some((resp, 60, None));
    }

    if function != 0x11 {
        push_line(
            evidence,
            "modbus_fc11_unexpected_function",
            &format!("0x{:02X}", function),
        );
        return None;
    }
    if function & 0x80 != 0 {
        let exception_code = resp[8];
        let desc = modbus_exception_description(exception_code);
        push_line(
            evidence,
            "modbus_exception_fc11",
            &format!("0x{:02X} ({})", exception_code, desc),
        );
        return Some((resp, 60, None));
    }

    push_line(evidence, "modbus_function_fc11", "Report Server ID");

    let byte_count = resp[8] as usize;
    if resp.len() < 9 + byte_count {
        push_line(evidence, "modbus", "fc11_byte_count_mismatch");
        return Some((resp, 70, None));
    }

    let server_id = &resp[9..9 + byte_count];
    push_line(
        evidence,
        "modbus_server_id_bytes",
        &format!("{:02X?}", server_id),
    );

    let mut vendor_conf = None;

    if let Ok(s) = String::from_utf8(server_id.to_vec()) {
        push_line(evidence, "modbus_server_id_string", &s);

        let upper = s.to_uppercase();
        let vendor = if upper.contains("SIEMENS") {
            vendor_conf = Some(85);
            "siemens"
        } else if upper.contains("WAGO") {
            vendor_conf = Some(85);
            "wago"
        } else if upper.contains("SCHNEIDER") {
            vendor_conf = Some(85);
            "schneider"
        } else if upper.contains("BECKHOFF") {
            vendor_conf = Some(85);
            "beckhoff"
        } else if upper.contains("UNITRONICS") {
            vendor_conf = Some(85);
            "unitronics"
        } else if upper.contains("ABB") {
            vendor_conf = Some(85);
            "abb"
        } else if upper.contains("OMRON") {
            vendor_conf = Some(85);
            "omron"
        } else if upper.contains("RUSTLITE") {
            vendor_conf = Some(90);
            "rustlite"
        } else {
            "unknown"
        };

        push_line(evidence, "modbus_vendor", vendor);
    }


    // 80 = clean function + server ID parsed
    Some((resp, 80, vendor_conf))
}

async fn modbus_read_holding_registers(
    stream: &mut TcpStream,
    timeout_dur: Duration,
    evidence: &mut String,
) -> Option<u8> {
    // MBAP + PDU (Function 0x03)
    // 00 02 = Transaction ID
    // 00 00 = Protocol ID
    // 00 06 = Length
    // FF    = Unit ID
    // 03    = Function 0x03 (Read Holding Registers)
    // 00 00 = Starting address
    // 00 01 = Number of registers
    let request: [u8; 12] = [
        0x00, 0x02, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x06, // Length
        0xFF,       // Unit ID
        0x03,       // Function 0x03
        0x00, 0x00, // Starting address
        0x00, 0x01, // Number of registers
    ];

    if timeout(timeout_dur, stream.write_all(&request))
        .await
        .is_err()
    {
        push_line(evidence, "modbus", "send_error_fc03");
        return None;
    }

    let mut buf = [0u8; 1024];
    let n = match timeout(timeout_dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => {
            push_line(evidence, "modbus", "no_response_fc03");
            return None;
        }
    };

    let resp = &buf[..n];
    push_line(evidence, "modbus_raw_fc03", &format!("{:02X?}", resp));

    if resp.len() < 10 {
        push_line(evidence, "modbus", "short_response_fc03");
        return Some(60);
    }

    let function = resp[7];

    // Exception?
    if function & 0x80 != 0 {
        let exception_code = resp[8];
        let desc = modbus_exception_description(exception_code);
        push_line(
            evidence,
            "modbus_exception_fc03",
            &format!("0x{:02X} ({})", exception_code, desc),
        );
        return Some(60);
    }


    if function != 0x03 {
        push_line(
            evidence,
            "modbus_fc03_unexpected_function",
            &format!("0x{:02X}", function),
        );
        return Some(60);
    }

    push_line(evidence, "modbus_function_fc03", "Read Holding Registers");

    let byte_count = resp[8] as usize;
    if resp.len() < 9 + byte_count {
        push_line(evidence, "modbus", "fc03_byte_count_mismatch");
        return Some(70);
    }

    let registers = &resp[9..9 + byte_count];
    push_line(
        evidence,
        "modbus_registers",
        &format!("{:02X?}", registers),
    );

    // 80 = clean function + registers parsed
    Some(80)
}
fn modbus_exception_description(code: u8) -> &'static str {
    match code {
        0x01 => "Illegal Function",
        0x02 => "Illegal Data Address",
        0x03 => "Illegal Data Value",
        0x04 => "Server Device Failure",
        0x05 => "Acknowledge",
        0x06 => "Server Device Busy",
        0x08 => "Memory Parity Error",
        0x0A => "Gateway Path Unavailable",
        0x0B => "Gateway Target Device Failed to Respond",
        _    => "Unknown Exception",
    }
}

async fn modbus_read_input_registers(
    stream: &mut TcpStream,
    timeout_dur: Duration,
    evidence: &mut String,
) -> Option<u8> {
    // MBAP + PDU (Function 0x04)
    // 00 03 = Transaction ID
    // 00 00 = Protocol ID
    // 00 06 = Length
    // FF    = Unit ID
    // 04    = Function 0x04 (Read Input Registers)
    // 00 00 = Starting address
    // 00 01 = Number of registers
    let request: [u8; 12] = [
        0x00, 0x03, // Transaction ID
        0x00, 0x00, // Protocol ID
        0x00, 0x06, // Length
        0xFF,       // Unit ID
        0x04,       // Function 0x04
        0x00, 0x00, // Starting address
        0x00, 0x01, // Number of registers
    ];

    if timeout(timeout_dur, stream.write_all(&request))
        .await
        .is_err()
    {
        push_line(evidence, "modbus", "send_error_fc04");
        return None;
    }

    let mut buf = [0u8; 1024];
    let n = match timeout(timeout_dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => {
            push_line(evidence, "modbus", "no_response_fc04");
            return None;
        }
    };

    let resp = &buf[..n];
    push_line(evidence, "modbus_raw_fc04", &format!("{:02X?}", resp));

    if resp.len() < 10 {
        push_line(evidence, "modbus", "short_response_fc04");
        return Some(60);
    }

    let function = resp[7];

    if function & 0x80 != 0 {
        let exception_code = resp[8];
        let desc = modbus_exception_description(exception_code);
        push_line(
            evidence,
            "modbus_exception_fc04",
            &format!("0x{:02X} ({})", exception_code, desc),
        );
        return Some(60);
    }

    if function != 0x04 {
        push_line(
            evidence,
            "modbus_fc04_unexpected_function",
            &format!("0x{:02X}", function),
        );
        return Some(60);
    }

    push_line(evidence, "modbus_function_fc04", "Read Input Registers");

    let byte_count = resp[8] as usize;
    if resp.len() < 9 + byte_count {
        push_line(evidence, "modbus", "fc04_byte_count_mismatch");
        return Some(70);
    }

    let registers = &resp[9..9 + byte_count];
    push_line(
        evidence,
        "modbus_input_registers",
        &format!("{:02X?}", registers),
    );

    Some(80)
}
