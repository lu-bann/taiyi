use std::net::{IpAddr, Ipv4Addr};

use alloy_primitives::Address;
use clap::Parser;
use ethereum_consensus::{deneb::Context, networks::Network};
use taiyi_preconfer::spawn_service;
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

    /// taiyi escrow contract address
    #[clap(long = "taiyi_escrow_contract_addr")]
    pub taiyi_escrow_contract_addr: String,

    /// taiyi core contract address
    #[clap(long = "taiyi_core_contract_addr")]
    pub taiyi_core_contract_addr: String,

    /// taiyi proposer registry contract address
    #[clap(long = "taiyi_proposer_registry_contract_addr")]
    pub taiyi_proposer_registry_contract_addr: String,

    /// taiyi service url. Internal usage for taiyi base fee predict module
    #[clap(long)]
    pub taiyi_service_url: Option<String>,

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
        let taiyi_escrow_contract_addr: Address = self.taiyi_escrow_contract_addr.parse()?;
        let taiyi_core_contract_addr: Address = self.taiyi_core_contract_addr.parse()?;
        let taiyi_proposer_registry_contract_addr: Address =
            self.taiyi_proposer_registry_contract_addr.parse()?;
        spawn_service(
            taiyi_escrow_contract_addr,
            taiyi_core_contract_addr,
            taiyi_proposer_registry_contract_addr,
            self.rpc_url.clone(),
            self.beacon_rpc_url.clone(),
            self.taiyi_service_url.clone(),
            self.signer_mod_url.clone(),
            self.signer_mod_jwt.clone(),
            self.commit_boost_config_path.clone(),
            context,
        )
        .await?;

        Ok(())
    }
}
