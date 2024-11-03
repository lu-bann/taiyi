use clap::{Parser, Subcommand};
use taiyi_cmd::{
    initialize_tracing_log, BatchDelegateCommand, DelegateCommand, DepositCommand,
    GetDelegatedPreconferCommand, RegisterPreconferCommand,
};

#[derive(Debug, Parser)]
#[command(author, version, about = "taiyi-cli", long_about = None)]
pub struct Cli {
    /// The command to execute
    #[clap(subcommand)]
    command: Commands,
}

/// Commands to be executed
#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(name = "user-deposit")]
    Deposit(DepositCommand),

    #[command(name = "delegate")]
    Delegate(DelegateCommand),

    #[command(name = "batch-delegate")]
    BatchDelegate(BatchDelegateCommand),

    #[command(name = "get-delegated-preconfer")]
    GetDelegatedPreconfer(GetDelegatedPreconferCommand),

    #[command(name = "register-preconfer")]
    RegisterPreconfer(RegisterPreconferCommand),
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    initialize_tracing_log();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime build failed");
    match cli.command {
        Commands::Deposit(cmd) => runtime.block_on(async { cmd.execute().await }),
        Commands::Delegate(cmd) => runtime.block_on(async { cmd.execute().await }),
        Commands::BatchDelegate(cmd) => runtime.block_on(async { cmd.execute().await }),
        Commands::GetDelegatedPreconfer(cmd) => runtime.block_on(async { cmd.execute().await }),
        Commands::RegisterPreconfer(cmd) => runtime.block_on(async { cmd.execute().await }),
    }
}
