mod commands;

use clap::{Parser, Subcommand};
use commands::preconfer::PreconferCommand;

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
    #[command(name = "preconfer")]
    Preconfer(PreconferCommand),
}

pub fn run() -> eyre::Result<()> {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime build failed");
    match cli.command {
        Commands::Preconfer(preconfer) => {
            runtime.block_on(async {
                preconfer.execute().await.expect("preconfer run");
            });
            Ok(())
        }
    }
}
