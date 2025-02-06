use clap::Parser;
use fraud_proof_cli::{tracing_util::init_tracing_subscriber, Cli};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing_subscriber(cli.verbosity())?;

    match cli {
        Cli::ProveIFP(args) => fraud_proof_cli::prove_ifp::prove(args).await?,
        Cli::ProveNIFP(args) => fraud_proof_cli::prove_nifp::prove(args).await?,
    }

    Ok(())
}
