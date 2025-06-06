pub mod prove;
pub mod tracing_util;

#[derive(clap::Parser, Debug, Clone)]
#[command(name = "taiyi-fraud-proof-cli")]
#[command(bin_name = "taiyi-fraud-proof-cli")]
#[command(author, version, about, long_about = None)]
pub enum Cli {
    ProvePOI(prove::ProveArgs),
    ProvePONI(prove::ProveArgs),
}

impl Cli {
    pub fn verbosity(&self) -> u8 {
        match self {
            Cli::ProvePOI(args) => args.v,
            Cli::ProvePONI(args) => args.v,
        }
    }
}
