use clap::{ArgAction, Parser};

#[derive(Parser, Debug,Clone,Default)]
#[command(name = "rustlite-scan", about = "Fast async port scanner (TCP/UDP) in Rust")]
pub struct Cli {
    #[arg(short, long)]
    pub target: String,

    #[arg(short, long, default_value = "1-1024")]
    pub ports: String,

    #[arg(long, action = ArgAction::SetTrue)]
    pub udp: bool,

    #[arg(short = 'c', long, default_value_t = 1024)]
    pub concurrency: usize,

    #[arg(long, default_value_t = 800)]
    pub connect_timeout_ms: u64,

    #[arg(long, default_value_t = 1200)]
    pub udp_timeout_ms: u64,

    #[arg(long, default_value_t = 1)]
    pub udp_retries: u8,

    #[arg(long, default_value_t = 50)]
    pub udp_retry_backoff_ms: u64,

    // NEW: global UDP send rate (packets per second). 0 disables throttling.
    #[arg(long, default_value_t = 0)]
    pub udp_rate: u64,

    // NEW: token bucket burst capacity (how many can be sent at once).
    #[arg(long, default_value_t = 50)]
    pub udp_burst: u64,
    
    /// Per-host UDP packets per second (0 = disabled)
    #[arg(long, default_value_t = 0)]
    pub udp_rate_host: u64,

    /// Per-host UDP burst capacity
    #[arg(long, default_value_t = 10)]
    pub udp_burst_host: u64,

    #[arg(long, action = ArgAction::SetTrue)]
    pub json: bool,

    #[arg(long, action = ArgAction::SetTrue)]
    pub no_ping: bool,

    #[arg(long, action = ArgAction::SetTrue)]
    pub ping_only: bool,

    #[arg(long, default_value_t = 100)]
    pub ping_concurrency: usize,

    #[arg(long, default_value_t = 1000)]
    pub ping_timeout_ms: u64,
        /// Write full JSON output to file (path)
    #[arg(long, value_name = "FILE", default_value_t = String::new())]
    pub json_out: String,

    /// Write CSV output to file (path)
    #[arg(long, value_name = "FILE", default_value_t = String::new())]
    pub csv_out: String,
        /// Force override safety checks (use with care)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub force: bool,

    /// Path to a blocklist file (one CIDR or host per line) to skip targets
    #[arg(long, value_name = "FILE", default_value_t = String::new())]
    pub blocklist: String,

    /// Minimum per-host cooldown between UDP sends in milliseconds
    #[arg(long, default_value_t = 50)]
    pub host_cooldown_ms: u64,
    /// Print planned limiter settings per host and exit (no network activity)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub dry_run: bool,
        /// Write per-probe metrics as JSON Lines to this file (append). Optional.
    #[arg(long, value_name = "FILE", default_value = "")]
    pub metrics_out: String,

    #[structopt(long)]
    pub service_probes: bool, // enable service probes

    #[structopt(long, default_value = "500")]
    pub probe_timeout_ms: u64,

    #[structopt(long, default_value = "1")]
    pub metrics_sample: u64,
    pub tcp_connect_timeout_ms: i32, // 1 = emit all, 10 = 1/10

      /// Repeated key=value probe parameters. Use multiple times: --probe-param foo=bar --probe-param timeout_ms=2000
    #[arg(long = "probe-param", action = ArgAction::Append, value_name = "KEY=VALUE")]
    pub probe_params: Vec<String>,


}

impl Cli {
    pub fn parse() -> Self {
        Parser::parse()
    }
}
