use std::net::{IpAddr, Ipv4Addr};

use alloy::core::primitives::Address;
use clap::Parser;
use luban_preconfer::rpc::start_rpc_server;

#[derive(Debug, Parser)]
pub struct LubanStakeCommand {
    /// rpc url
    #[clap(long = "rpc_url")]
    pub rpc_url: String,

    #[clap(long = "phrase")]
    pub phrase: String,

    #[clap(long = "luban_proposer_registry_contract_addr")]
    pub luban_proposer_registry_contract_addr: String,
}

impl LubanStakeCommand {
    pub async fn execute(&self) -> eyre::Result<()> {
        Ok(())
    }
}
