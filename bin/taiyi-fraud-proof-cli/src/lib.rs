pub mod prove_poi;
pub mod prove_poni;
pub mod tracing_util;

#[derive(clap::Parser, Debug, Clone)]
#[command(name = "taiyi-fraud-proof-cli")]
#[command(bin_name = "taiyi-fraud-proof-cli")]
#[command(author, version, about, long_about = None)]
pub enum Cli {
    ProvePOI(prove_poi::ProveArgs),
    ProvePONI(prove_poni::ProveArgs),
}

impl Cli {
    pub fn verbosity(&self) -> u8 {
        match self {
            Cli::ProvePOI(args) => args.v,
            Cli::ProvePONI(args) => args.v,
        }
    }
}
