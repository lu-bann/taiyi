use clap::{Parser, Subcommand};
use taiyi_cmd::{initialize_tracing_log, UnderwriterCommand};

#[derive(Debug, Parser)]
#[command(author, version, about = "taiyi", long_about = None)]
pub struct Cli {
    /// The command to execute
    #[clap(subcommand)]
    command: Commands,
}

/// Commands to be executed
#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(name = "underwriter")]
    Underwriter(UnderwriterCommand),
}

pub fn run() -> eyre::Result<()> {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime build failed");
    match cli.command {
        Commands::Underwriter(underwriter) => {
            runtime.block_on(async { underwriter.execute().await })?;
            Ok(())
        }
    }
}

fn main() {
    initialize_tracing_log();
    if let Err(err) = run() {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
