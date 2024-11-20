use clap::{Parser, Subcommand};
use taiyi_cmd::{
    initialize_tracing_log, BatchRegisterCommand, GetValidatorCommand, RegisterCommand,
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
    #[command(name = "register-validator")]
    Register(RegisterCommand),

    #[command(name = "batch-register-validators")]
    BatchRegister(BatchRegisterCommand),

    #[command(name = "get-validator")]
    GetValidator(GetValidatorCommand),
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    initialize_tracing_log();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime build failed");
    match cli.command {
        Commands::Register(cmd) => runtime.block_on(async { cmd.execute().await }),
        Commands::BatchRegister(cmd) => runtime.block_on(async { cmd.execute().await }),
        Commands::GetValidator(cmd) => runtime.block_on(async { cmd.execute().await }),
    }
}
