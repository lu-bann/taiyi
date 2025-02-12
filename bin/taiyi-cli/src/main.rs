use clap::{Parser, Subcommand};
use taiyi_cmd::{
    initialize_tracing_log, DelegateCommand, DepositCommand, DeregisterValidatorAVSCommand,
    OperatorInfoCommand, RegisterValidatorAVSCommand, RegisterValidatorsCommand,
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
    #[command(name = "register-validator-avs")]
    RegisterValidatorAVS(RegisterValidatorAVSCommand),

    #[command(name = "deregister-validator-avs")]
    DeregisterValidatorAVS(DeregisterValidatorAVSCommand),

    #[command(name = "deposit")]
    Deposit(DepositCommand),

    #[command(name = "delegate")]
    Delegate(DelegateCommand),

    #[command(name = "register-validators")]
    RegisterValidators(RegisterValidatorsCommand),

    #[command(name = "operator-info")]
    OperatorInfo(OperatorInfoCommand),
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    initialize_tracing_log();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime build failed");
    match cli.command {
        Commands::RegisterValidatorAVS(cmd) => runtime.block_on(async { cmd.execute().await }),
        Commands::DeregisterValidatorAVS(cmd) => runtime.block_on(async { cmd.execute().await }),
        Commands::Deposit(cmd) => runtime.block_on(async { cmd.execute().await }),
        Commands::Delegate(cmd) => runtime.block_on(async { cmd.execute().await }),
        Commands::RegisterValidators(cmd) => runtime.block_on(async { cmd.execute().await }),
        Commands::OperatorInfo(cmd) => runtime.block_on(async { cmd.execute().await }),
    }
}
