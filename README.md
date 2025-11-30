A simple Rust clone of NMAP
#### Per-probe metrics (JSON Lines)

**Flag**: `--metrics-out <FILE>`

When provided, the scanner writes one JSON object per probe attempt to the given file (JSON Lines / newline-delimited JSON). Each line is a compact JSON object describing the probe event and some runtime metadata. The file is append-only and safe to stream while the scan runs.

**Example usage**
```bash
cargo run -- --target 127.0.0.1 --ports 53 --udp --metrics-out metrics.jsonl




---

### Cargo.toml feature for test helpers
Add this feature to `Cargo.toml` so integration tests can enable `refill_once` without exposing it in normal builds.

```toml
[features]
# test_helpers exposes small helpers used only by tests and integration tests
test_helpers = []

