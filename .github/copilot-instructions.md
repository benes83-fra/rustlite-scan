# Rustlite-Scan AI Development Guide

**rustlite-scan** is a high-performance async port scanner written in Rust, supporting TCP/UDP protocols with advanced rate limiting, retry logic, and blocklist filtering.

## Architecture Overview

### Core Pipeline
- **CLI Input** (`cli.rs`): Clap-based argument parsing with extensive configuration options
- **Target Expansion** (`netutils.rs`): Converts CIDR blocks, hostnames, and IP ranges into individual targets
- **Port Parsing** (`netutils.rs`): Handles comma-separated and range notation (e.g., `80,443,1000-1024`)
- **Main Scan Loop** (`scan.rs`): Orchestrates concurrent probes with rate limiting and blocklist filtering
- **Result Output**: JSON/CSV file writing with atomic temp-file operations

### Probe Modules
- **TCP Probe** (`probes/tcp.rs`): Performs `TcpStream::connect()` with service-specific banner grabbing
  - Ports 80/443/8080: Sends HTTP HEAD request
  - Port 22: SSH banner read
  - Port 25: SMTP banner read
- **UDP Probe** (`probes/udp.rs`): DNS and NTP packet crafting with retries and per-probe statistics
  - DNS (port 53): Constructs raw DNS query packet
  - NTP (port 123): Sends NTP v3 packet (0x1B header)
  - Configurable retries with exponential backoff (`--udp-retries`, `--udp-retry-backoff-ms`)
- **ICMP Probe** (`probes/icmp.rs`): Cross-platform system ping wrapper with IPv6 support

### Rate Limiting Strategy
Two-tier rate limiting via `RateLimiter` (`utils/ratelimit.rs`):
1. **Global limiter**: Applied to all UDP packets globally (`--udp-rate`)
2. **Per-host limiter**: Applied per-host to prevent flooding (`--udp-rate-host`)
- Uses token-bucket algorithm with semaphore
- Burst capacity limits burst sends (`--udp-burst`, `--udp-burst-host`)
- Refills every 100ms; 0 disables throttling

## Project Conventions

### Type System
- `PortResult`: Single port result with state ("open"/"closed"/"filtered"/"unknown")
- `UdpMetrics`: Aggregate stats per host (attempts, retries, timeouts, successes, packets_sent/received)
- `HostResult`: Contains host name, IP, all results, and optional UDP metrics

### Error Handling
- Primary: `anyhow::Result<T>` for recoverable errors
- Atomic file writes: `.tmp` file pattern to prevent corruption on crash
- Network errors degrade gracefully to "unknown" state rather than panicking

### Async Model
- `#[tokio::main]` entry point with `tokio::runtime::Runtime`
- `FuturesUnordered` for unordered concurrent task batching (no ordering guarantee)
- `Semaphore` for concurrency control (`--concurrency` flag controls max concurrent probes)
- Signal handlers for graceful shutdown (Ctrl+C)

### Data Output Formats
- **JSON**: Flat structure with per-port results and UDP metrics
- **CSV**: Denormalized one-row-per-port with all UDP metrics repeated per host
- Atomic writes protect against partial file corruption

## Key Workflows

### Building
```bash
cargo build --release
```

### Running Tests
```bash
cargo test
```
Key test files:
- `tests/netutils_unit.rs`: Port and target expansion logic
- `tests/udp_retry.rs`: Retry and backoff behavior
- `tests/udp_dns.rs`: DNS packet parsing
- `tests/csv_roundtrip.rs`: CSV serialization

### Common Development Tasks

#### Adding a New Probe Type
1. Create `src/probes/new_protocol.rs` with an async `new_protocol_probe(ip: &str, port: u16, ...) -> PortResult`
2. Update `src/probes/mod.rs` to export the function
3. Integrate into `scan.rs` scan loop by adding conditional logic based on port or flag

#### Adjusting Rate Limiting
- Global throttle: `--udp-rate N` (packets per second, 0=disabled)
- Per-host throttle: `--udp-rate-host N`
- Burst capacity: `--udp-burst 50`, `--udp-burst-host 10`
- Host cooldown: `--host-cooldown-ms 50` (minimum delay between sends to same host)

#### Modifying Output Schema
- Edit `PortResult` or `UdpMetrics` in `types.rs`
- Update CSV writer in `scan.rs` `write_csv_file()` and `write_csv_file_atomic()`
- Update JSON serialization logic (serde handles automatically)

#### Filtering Targets
- Use `--blocklist /path/to/file` with CIDR blocks or individual IPs (one per line)
- Comments starting with `#` are ignored
- `is_blocked()` function in `scan.rs` checks membership

## Common Patterns

### Timeout Pattern
All probes use `tokio::time::timeout(Duration::from_millis(...), future)` to enforce hard limits.

### IPv6 Awareness
- Network parsing: Use `IpAddr` enum (not String) for proper IPv6 sockaddr handling
- ICMP: Platform-specific ping invocation with `-6` flag for IPv6

### Cross-Platform Considerations
- ICMP: Windows uses `-n 1 -w <ms>`; Unix uses `-c 1 -W <seconds>`
- File paths: Atomic writes use `.tmp` pattern (works on both POSIX and Windows)

## Important Files Reference

| File | Purpose |
|------|---------|
| `src/cli.rs` | CLI definition with all flags and defaults |
| `src/scan.rs` | Main orchestration loop, blocklist loading, atomic file I/O |
| `src/types.rs` | Core data structures (PortResult, UdpMetrics, HostResult) |
| `src/netutils.rs` | Target/port expansion and hostname resolution |
| `src/probes/*.rs` | Protocol implementations |
| `src/utils/ratelimit.rs` | Token-bucket rate limiter with semaphore |

## Debugging Tips

- Enable `RUST_LOG=debug` for verbose output (if logging is configured)
- Check `target/debug/` build artifacts for incremental builds
- UDP timeouts/failures appear as "filtered" state; check `--udp-timeout-ms` if too aggressive
- High concurrency with low rate limits may cause "connection refused" on source port exhaustion—adjust `--concurrency` and cooldown
