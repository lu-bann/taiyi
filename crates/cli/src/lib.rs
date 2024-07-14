mod commands;

use clap::{Parser, Subcommand};

use commands::preconfer::PreconferCommand;

#[derive(Debug, Parser)]
#[command(author, version, about = "luban", long_about = None)]
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
    // #[command(name = "luban-stake")]
    // LubanStake(LubanStake),
}

pub fn run() -> eyre::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Preconfer(preconfer) => {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime build failed")
                .block_on(async {
                    preconfer.execute().await.expect("preconfer run");
                });
            Ok(())
        }
    }
}
