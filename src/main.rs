mod cli;
mod types;
mod netutils;
mod scan;
mod probes;
mod utils;

use anyhow::Result;
use cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    scan::run(cli).await
}
