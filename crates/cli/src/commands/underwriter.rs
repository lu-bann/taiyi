use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use alloy::primitives::Address;
use clap::Parser;
use eyre::{eyre, ContextCompat};

#[derive(Debug, Parser)]
pub struct UnderwriterCommand {
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

    /// Hex string representing the fork version, e.g., "0x00000000" for Mainnet, "0x01017000" for Holesky
    #[clap(long)]
    pub fork_version: String,

    #[clap(long)]
    pub genesis_timestamp: u64,

    /// consensus client rpc url
    #[clap(long, value_delimiter = ',')]
    pub relay_url: String,

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

impl UnderwriterCommand {
    pub async fn execute(&self) -> eyre::Result<()> {
        //     if let Some(metrics_port) = self.metrics_port {
        //         init_metrics(metrics_port)?;
        //     }

        println!("Starting on port {}", self.taiyi_rpc_port);
        // decode the fork version from hex string
        println!("Fork version: {}", self.fork_version);
        let fork_version: [u8; 4] = {
            hex::decode(
                self.fork_version
                    .strip_prefix("0x")
                    .wrap_err("Fork version must start with '0x'")?,
            )?
            .try_into()
            .map_err(|x| eyre!("could not convert vec to slice: {x:?}"))?
        };

        taiyi_underwriter::api::run(
            self.taiyi_rpc_addr,
            self.taiyi_rpc_port,
            self.execution_rpc_url.clone(),
            self.beacon_rpc_url.clone(),
            self.taiyi_service_url.clone(),
            self.bls_sk.clone(),
            self.ecdsa_sk.clone(),
            self.relay_url.clone(),
            Address::from_str(&self.taiyi_escrow_address)?,
            fork_version,
            self.genesis_timestamp,
        )
        .await?;
        Ok(())
    }
}
