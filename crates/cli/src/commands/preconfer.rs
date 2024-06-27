use std::net::{IpAddr, Ipv4Addr};

use alloy_core::primitives::Address;
use clap::Parser;
use luban_preconfer::rpc::start_rpc_server;
#[derive(Debug, Parser)]
pub struct PreconferCommand {
    /// jsonrpc service address to listen on.
    #[clap(long = "addr", default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
    pub addr: IpAddr,

    /// jsonrpc service port to listen on.
    #[clap(long = "port", default_value_t = 5656)]
    pub port: u16,

    /// rpc url
    #[clap(long = "rpc_url")]
    pub rpc_url: String,

    /// luban escrow contract address
    #[clap(long = "luban_escrow_contract_addr")]
    pub luban_escrow_contract_addr: String,

    #[clap(long)]
    pub luban_service_url: String,

    /// commit boost url
    #[clap(long)]
    pub commit_boost_url: String,
}

impl PreconferCommand {
    pub async fn execute(&self) -> eyre::Result<()> {
        let addr = self.addr;
        let port = self.port;
        let luban_escrow_contract_addr: Address = self.luban_escrow_contract_addr.parse()?;
        start_rpc_server(
            addr,
            port,
            luban_escrow_contract_addr,
            self.rpc_url.clone(),
            self.luban_service_url.clone(),
            self.commit_boost_url.clone(),
        )
        .await?;
        Ok(())
    }
}
