use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

use alloy_primitives::Address;
use blst::min_pk::SecretKey;
use clap::Parser;
use ethereum_consensus::{deneb::Context, networks::Network};
use eyre::eyre;
use taiyi_preconfer::{chainspec_builder, create_provider_factory, spawn_service, SimulationPool};
use tokio_util::sync::CancellationToken;
#[derive(Debug, Parser)]
pub struct PreconferCommand {
    /// jsonrpc service address to listen on.
    #[clap(long = "taiyi_rpc_addr", default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
    pub taiyi_rpc_addr: IpAddr,

    /// jsonrpc service port to listen on.
    #[clap(long = "taiyi_rpc_port", default_value_t = 5656)]
    pub taiyi_rpc_port: u16,

    /// execution client rpc url
    #[clap(long = "execution_client_url")]
    pub execution_client_url: String,

    /// consensus client rpc url
    #[clap(long = "beacon_client_url")]
    pub beacon_client_url: String,

    /// A BLS private key to use for signing
    #[clap(long = "bls_sk")]
    pub bls_sk: String,

    /// A BLS private key to use for signing
    #[clap(long = "ecdsa_sk")]
    pub ecdsa_sk: String,

    /// network
    #[clap(long = "network")]
    pub network: String,

    /// consensus client rpc url
    #[clap(long = "relay_url")]
    pub relay_url: Vec<String>,

    /// taiyi core contract address
    #[clap(long = "taiyi_core_contract_addr")]
    pub taiyi_core_contract_addr: String,

    /// taiyi proposer registry contract address
    #[clap(long = "taiyi_proposer_registry_contract_addr")]
    pub taiyi_proposer_registry_contract_addr: String,

    /// taiyi service url. Internal usage for taiyi base fee predict module
    #[clap(long)]
    pub taiyi_service_url: Option<String>,

    /// reth data dir
    #[clap(long = "reth_data_dir")]
    pub reth_data_dir: PathBuf,

    /// simulation threads
    #[clap(long = "simulation_threads")]
    pub simulation_threads: usize,

    /// TaiyiCore contract owner address
    #[clap(long = "owner")]
    pub owner: String,
}

impl PreconferCommand {
    pub async fn execute(&self) -> eyre::Result<()> {
        let network: Network = self.network.clone().into();
        let chain_spec = chainspec_builder(network.clone());
        let provider_factory = create_provider_factory(&self.reth_data_dir, chain_spec);
        let context: Context = network.try_into()?;

        let taiyi_core_contract_addr: Address = self.taiyi_core_contract_addr.parse()?;
        let taiyi_proposer_registry_contract_addr: Address =
            self.taiyi_proposer_registry_contract_addr.parse()?;

        let bls_private_key = SecretKey::from_bytes(&hex::decode(
            self.bls_sk.strip_prefix("0x").unwrap_or(&self.bls_sk),
        )?)
        .map_err(|e| eyre!("Failed decoding preconfer private key: {:?}", e))?;

        let ecdsa_signer = alloy_signer_local::PrivateKeySigner::from_signing_key(
            k256::ecdsa::SigningKey::from_slice(&hex::decode(
                self.ecdsa_sk.strip_prefix("0x").unwrap_or(&self.ecdsa_sk),
            )?)?,
        );

        // spawn simulation service
        let _simulation_pool = SimulationPool::new(provider_factory, 1, CancellationToken::new());

        spawn_service(
            taiyi_core_contract_addr,
            taiyi_proposer_registry_contract_addr,
            self.execution_client_url.clone(),
            self.beacon_client_url.clone(),
            self.taiyi_service_url.clone(),
            context,
            self.taiyi_rpc_addr,
            self.taiyi_rpc_port,
            bls_private_key,
            ecdsa_signer,
            self.relay_url.clone(),
            self.owner.parse()?,
        )
        .await?;

        Ok(())
    }
}
