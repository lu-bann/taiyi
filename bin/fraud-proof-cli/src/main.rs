use clap::Parser;
use fraud_proof_cli::tracing_util::init_tracing_subscriber;
use fraud_proof_cli::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing_subscriber(cli.verbosity())?;

    match cli {
        Cli::Prove(args) => fraud_proof_cli::prove::prove(args).await?,
    }

    Ok(())
}
