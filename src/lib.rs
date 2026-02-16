pub mod cli;
pub mod netutils;
pub mod os;
pub mod probes;
pub mod scan;
pub mod service;
pub mod types;
pub mod utils;
pub use scan::run;
pub use tracing_subscriber;
pub use tracing_subscriber::filter::EnvFilter;

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
}
