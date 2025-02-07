use eyre::eyre;
use tracing::Level;
use tracing_log::{log::LevelFilter, LogTracer};

pub fn init_tracing_subscriber(verbosity_level: u8) -> eyre::Result<()> {
    LogTracer::builder()
        .with_max_level(match verbosity_level {
            0 => LevelFilter::Info,
            1 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        })
        .init()?;

    let subscriber = tracing_subscriber::fmt()
        .with_max_level(match verbosity_level {
            0 => Level::INFO,
            1 => Level::DEBUG,
            _ => Level::TRACE,
        })
        .finish();
    tracing::subscriber::set_global_default(subscriber).map_err(|e| eyre!(e))
}
