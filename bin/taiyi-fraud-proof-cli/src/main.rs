use clap::Parser;
use sp1_sdk::include_elf;
use taiyi_fraud_proof_cli::{prove::prove, tracing_util::init_tracing_subscriber, Cli};

const ELF_PONI: &[u8] = include_elf!("taiyi-poni");
const ELF_POI: &[u8] = include_elf!("taiyi-poi");

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    init_tracing_subscriber(cli.verbosity())?;

    match cli {
        Cli::ProvePOI(args) => prove(args, ELF_POI).await?,
        Cli::ProvePONI(args) => prove(args, ELF_PONI).await?,
    }

    Ok(())
}
