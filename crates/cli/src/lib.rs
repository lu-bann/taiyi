mod commands;

use clap::{Parser, Subcommand};
use commands::{
    luban_escrow_deposit::LubanEscrowDepositCommand, luban_stake::LubanStakeCommand,
    preconfer::PreconferCommand,
};

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
    #[command(name = "luban-stake")]
    LubanStake(LubanStakeCommand),
    #[command(name = "luban-escrow-deposit")]
    LubanEscrowDeposit(LubanEscrowDepositCommand),
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
        Commands::LubanStake(luban_stake) => {
            runtime.block_on(async { luban_stake.execute().await })
        }
        Commands::LubanEscrowDeposit(luban_escrow_deposit) => {
            runtime.block_on(async { luban_escrow_deposit.execute().await })
        }
    }
}
