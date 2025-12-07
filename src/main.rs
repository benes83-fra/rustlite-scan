mod cli;
mod types;
mod netutils;
mod scan;
mod probes;
mod utils;
mod service;
use tracing_subscriber;
use tracing_subscriber::{EnvFilter};
use anyhow::Result;
use cli::Cli;
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
}
#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    scan::run(cli).await
}
