pub mod prove;
pub mod tracing_util;

#[derive(clap::Parser, Debug, Clone)]
#[command(name = "fraud-proof-cli")]
#[command(bin_name = "fraud-proof-cli")]
#[command(author, version, about, long_about = None)]
pub enum Cli {
    Prove(prove::ProveArgs),
}

impl Cli {
    pub fn verbosity(&self) -> u8 {
        match self {
            Cli::Prove(args) => args.v,
        }
    }
}
