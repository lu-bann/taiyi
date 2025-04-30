use clap::{Parser, Subcommand};
use taiyi_cmd::{
    initialize_tracing_log, DelegateCommand, GetStrategiesStakesCommand, OperatorInfoCommand,
    RegisterForOperatorSetsCommand, RegisterValidatorsCommand,
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
    #[command(name = "delegate")]
    Delegate(DelegateCommand),

    #[command(name = "register-validators")]
    RegisterValidators(RegisterValidatorsCommand),

    #[command(name = "operator-info")]
    OperatorInfo(OperatorInfoCommand),

    #[command(name = "get-strategies-stakes")]
    GetStrategiesStakes(GetStrategiesStakesCommand),

    #[command(name = "register-for-operator-sets")]
    RegisterForOperatorSets(RegisterForOperatorSetsCommand),
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    initialize_tracing_log();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime build failed");
    match cli.command {
        Commands::Delegate(cmd) => runtime.block_on(async { cmd.execute().await }),
        Commands::RegisterValidators(cmd) => runtime.block_on(async { cmd.execute().await }),
        Commands::OperatorInfo(cmd) => runtime.block_on(async { cmd.execute().await }),
        Commands::GetStrategiesStakes(cmd) => runtime.block_on(async { cmd.execute().await }),
        Commands::RegisterForOperatorSets(cmd) => runtime.block_on(async { cmd.execute().await }),
    }
}
