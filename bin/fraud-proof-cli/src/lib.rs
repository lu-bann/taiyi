pub mod prove_ifp;
pub mod prove_nifp;
pub mod tracing_util;

#[derive(clap::Parser, Debug, Clone)]
#[command(name = "fraud-proof-cli")]
#[command(bin_name = "fraud-proof-cli")]
#[command(author, version, about, long_about = None)]
pub enum Cli {
    ProveIFP(prove_ifp::ProveArgs),
    ProveNIFP(prove_nifp::ProveArgs),
}

impl Cli {
    pub fn verbosity(&self) -> u8 {
        match self {
            Cli::ProveIFP(args) => args.v,
            Cli::ProveNIFP(args) => args.v,
        }
    }
}
