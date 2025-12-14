rustlite-scan
A lightweight Rust-based port scanner inspired by Nmap. It’s intended as a compact, educational tool for fast host/port discovery and simple result export.

Key features
Rust implementation focused on simplicity and performance.

Port scanning for one or multiple targets (CLI-driven).

Exportable results in JSON and CSV formats (example outputs included in the repo).

Automated tests and a small test suite under tests/. including docker startup scripts

Features and exensible set of probes to discover different services in the network
like :
dns.rs                                                               
ftp.rs                                                               
helper.rs                                                            
http.rs                                                              
https.rs                                                             
icmp.rs                                                              
imap.rs                                                              
ldap.rs                                                              
mod.rs                                                               
nbns.rs                                                              
nbns_helper.rs                                                       
pop3.rs                                                              
postgres.rs                                                          
rdp.rs                                                               
smb.rs                                                               
smtp.rs                                                              
snmp.rs                                                              
ssh.rs                                                               
tcp.rs                                                               
tls.rs                                                               
udp.rs                                                               




Why use rustlite-scan
Educational: good for learning Rust networking and async patterns.

Lightweight: fewer features than Nmap but easier to read and extend.

Portable: builds with Cargo and runs on any platform supported by Rust.

Installation
bash
# Clone the repo
git clone https://github.com/benes83-fra/rustlite-scan.git
cd rustlite-scan

# Build with Cargo
cargo build --release
Quick usage
Replace <target> and <ports> with your values.

bash
# Basic scan (example)
cargo run --release -- --target 192.168.1.1 --ports 1-1024

# Scan multiple targets (example)
cargo run --release -- --targets targets.txt --ports 22,80,443

--probe-param key=value is good. Document conventions in --help and README:

usernames=postgres,rustlite

dbnames=postgres,rustlite_test

timeout_ms=3000

max_attempts=5

probe_mode=aggressive (must be set to enable credential probing)

Consider adding --probe-param-file path.json for complex runs (optional).



# Save results
cargo run --release -- --target 192.168.1.1 --ports 1-1024 --output results.json
Note: The repository includes example results.json and results.csv to show the output format and fields.

Output formats
JSON — structured, machine-readable results suitable for further processing.

CSV — quick tabular export for spreadsheets and simple reporting. Example files are present in the repository root to illustrate the schema.

Tests
Run the test suite with Cargo:

bash
cargo test
Tests are located in the tests/ directory and exercise core scanning logic and utilities.

Development notes & suggestions
Document CLI flags explicitly in README (examples above are placeholders — replace with the actual flags implemented in src/).

Add examples for common workflows (single-host, subnet, file-based targets).

Clarify concurrency model (sync vs async) and any rate-limiting or timeout defaults.

Include a CONTRIBUTING.md with coding style, testing, and PR guidelines to encourage contributions.

Contributing
Fork, create a feature branch, add tests, and open a PR. Keep changes small and focused.

Please run cargo fmt and cargo clippy before submitting.