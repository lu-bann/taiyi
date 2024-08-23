use std::net::{IpAddr, Ipv4Addr};

use alloy_primitives::Address;
use clap::Parser;
use ethereum_consensus::{deneb::Context, networks::Network};
use luban_preconfer::spawn_service;
#[derive(Debug, Parser)]
pub struct PreconferCommand {
    /// jsonrpc service address to listen on.
    #[clap(long = "addr", default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
    pub addr: IpAddr,

    /// jsonrpc service port to listen on.
    #[clap(long = "port", default_value_t = 5656)]
    pub port: u16,

    /// execution client rpc url
    #[clap(long = "rpc_url")]
    pub rpc_url: String,

    /// network
    #[clap(long = "network")]
    pub network: String,

    /// consensus client rpc url
    #[clap(long = "beacon_rpc_url")]
    pub beacon_rpc_url: String,

    /// luban escrow contract address
    #[clap(long = "luban_escrow_contract_addr")]
    pub luban_escrow_contract_addr: String,

    /// luban core contract address
    #[clap(long = "luban_core_contract_addr")]
    pub luban_core_contract_addr: String,

    /// luban proposer registry contract address
    #[clap(long = "luban_proposer_registry_contract_addr")]
    pub luban_proposer_registry_contract_addr: String,

    /// luban service url. Internal usage for luban base fee predict module
    #[clap(long)]
    pub luban_service_url: Option<String>,

    /// commit boost url
    #[clap(long)]
    pub signer_mod_url: String,

    /// commit boost jwt token
    #[clap(long)]
    pub signer_mod_jwt: String,

    #[clap(long)]
    pub commit_boost_config_path: String,
}

impl PreconferCommand {
    pub async fn execute(&self) -> eyre::Result<()> {
        let network: Network = self.network.clone().into();
        let context: Context = network.try_into()?;
        let luban_escrow_contract_addr: Address = self.luban_escrow_contract_addr.parse()?;
        let luban_core_contract_addr: Address = self.luban_core_contract_addr.parse()?;
        let luban_proposer_registry_contract_addr: Address =
            self.luban_proposer_registry_contract_addr.parse()?;
        spawn_service(
            luban_escrow_contract_addr,
            luban_core_contract_addr,
            luban_proposer_registry_contract_addr,
            self.rpc_url.clone(),
            self.beacon_rpc_url.clone(),
            self.luban_service_url.clone(),
            self.signer_mod_url.clone(),
            self.signer_mod_jwt.clone(),
            self.commit_boost_config_path.clone(),
            context,
        )
        .await?;

        Ok(())
    }
}
