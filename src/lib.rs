pub mod cli;
pub mod types;
pub mod netutils;
pub mod scan;
pub mod probes;
pub mod utils;
pub mod service;

pub use tracing_subscriber;
pub use tracing_subscriber::filter::EnvFilter;
pub use scan::run;

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt() 
        .with_env_filter(EnvFilter::from_default_env())
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
}