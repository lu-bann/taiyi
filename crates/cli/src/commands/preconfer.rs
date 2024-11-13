use std::net::{IpAddr, Ipv4Addr};

use blst::min_pk::SecretKey;
use clap::Parser;
use ethereum_consensus::{deneb::Context, networks::Network};
use eyre::eyre;
use taiyi_preconfer::{metrics::preconfer::init_metrics, spawn_service};
#[derive(Debug, Parser)]
pub struct PreconferCommand {
    /// jsonrpc service address to listen on.
    #[clap(long = "taiyi_rpc_addr", default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
    pub taiyi_rpc_addr: IpAddr,

    /// jsonrpc service port to listen on.
    #[clap(long = "taiyi_rpc_port", default_value_t = 5656)]
    pub taiyi_rpc_port: u16,

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
    #[clap(long = "relay_url", value_delimiter = ',')]
    pub relay_url: Vec<String>,

    /// metrics port
    #[clap(long)]
    pub metrics_port: Option<u16>,
}

impl PreconferCommand {
    pub async fn execute(&self) -> eyre::Result<()> {
        let network: Network = self.network.clone().into();
        let context: Context = network.try_into()?;

        let bls_private_key = SecretKey::from_bytes(&hex::decode(
            self.bls_sk.strip_prefix("0x").unwrap_or(&self.bls_sk),
        )?)
        .map_err(|e| eyre!("Failed decoding preconfer private key: {:?}", e))?;

        let ecdsa_signer = alloy_signer_local::PrivateKeySigner::from_signing_key(
            k256::ecdsa::SigningKey::from_slice(&hex::decode(
                self.ecdsa_sk.strip_prefix("0x").unwrap_or(&self.ecdsa_sk),
            )?)?,
        );

        if let Some(metrics_port) = self.metrics_port {
            init_metrics(metrics_port)?;
        }

        spawn_service(
            context,
            self.taiyi_rpc_addr,
            self.taiyi_rpc_port,
            bls_private_key,
            ecdsa_signer,
            self.relay_url.clone(),
        )
        .await?;

        Ok(())
    }
}
