use std::net::{IpAddr, Ipv4Addr};

use clap::Parser;
use ethereum_consensus::{deneb::Context, networks::Network};
use taiyi_preconfer::{metrics::models::init_metrics, spawn_service};
#[derive(Debug, Parser)]
pub struct PreconferCommand {
    /// jsonrpc service address to listen on.
    #[clap(long, env="TAIYI_RPC_ADDR", default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
    pub taiyi_rpc_addr: IpAddr,

    /// jsonrpc service port to listen on.
    #[clap(long, env = "TAIYI_RPC_PORT", default_value_t = 5656)]
    pub taiyi_rpc_port: u16,

    /// execution client rpc url
    #[clap(long, env = "EXECUTION_RPC_URL")]
    pub execution_rpc_url: String,

    /// consensus client rpc url
    #[clap(long, env = "BEACON_RPC_URL")]
    pub beacon_rpc_url: String,

    /// A BLS private key to use for signing
    #[clap(long, env = "TAIYI_BLS_SK")]
    pub bls_sk: String,

    /// A BLS private key to use for signing
    #[clap(long, env = "TAIYI_ECDSA_SK")]
    pub ecdsa_sk: String,

    /// network
    #[clap(long, env = "NETWORK")]
    pub network: String,

    /// consensus client rpc url
    #[clap(long, value_delimiter = ',')]
    pub relay_url: Vec<String>,

    /// taiyi service url. Internal usage for taiyi base fee predict module
    #[clap(long)]
    pub taiyi_service_url: Option<String>,

    /// Taiyi Escrow contract address
    #[clap(long)]
    pub taiyi_escrow_address: String,

    /// metrics port
    #[clap(long)]
    pub metrics_port: Option<u16>,
}

impl PreconferCommand {
    pub async fn execute(&self) -> eyre::Result<()> {
        let network: Network = self.network.clone().into();
        let context: Context = network.try_into()?;

        if let Some(metrics_port) = self.metrics_port {
            init_metrics(metrics_port)?;
        }

        let relay_url = self.relay_url.iter().map(|url| url.parse().expect("relay urls")).collect();

        spawn_service(
            self.execution_rpc_url.clone(),
            self.beacon_rpc_url.clone(),
            context,
            self.taiyi_rpc_addr,
            self.taiyi_rpc_port,
            self.bls_sk.clone(),
            self.ecdsa_sk.clone(),
            relay_url,
            self.taiyi_escrow_address.parse()?,
            self.taiyi_service_url.clone(),
        )
        .await?;

        Ok(())
    }
}
