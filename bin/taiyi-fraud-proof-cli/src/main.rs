use clap::Parser;
use taiyi_fraud_proof_cli::{tracing_util::init_tracing_subscriber, Cli};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    init_tracing_subscriber(cli.verbosity())?;

    match cli {
        Cli::ProvePOI(args) => taiyi_fraud_proof_cli::prove_poi::prove(args).await?,
        Cli::ProvePONI(args) => taiyi_fraud_proof_cli::prove_poni::prove(args).await?,
    }

    Ok(())
}
