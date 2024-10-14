use std::str::FromStr;

use tracing::Level;

fn main() {
    initialize_tracing_log();
    if let Err(err) = taiyi_cli::run() {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
pub fn initialize_tracing_log() {
    let level_env = std::env::var("RUST_LOG").unwrap_or("info".to_owned());
    let level = if let Ok(level) = Level::from_str(&level_env) {
        level
    } else {
        eprint!("Invalid log level {level_env}, defaulting to info");
        Level::INFO
    };

    tracing_subscriber::fmt()
        .compact()
        .with_max_level(level)
        .with_target(true)
        .with_file(true)
        .init();
}
