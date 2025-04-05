use std::str::FromStr;

use alloy_primitives::Address;
use alloy_provider::ProviderBuilder;
use clap::Parser;
use eyre::Result;
use reqwest::Url;
use taiyi_contracts::{AVSType, ProposerRegistry};
use tracing::info;

#[derive(Debug, Clone, Copy)]
enum AvsType {
    Validator,
    Underwriter,
}

impl FromStr for AvsType {
    type Err = eyre::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "validator" => Self::Validator,
            "underwriter" => Self::Underwriter,
            _ => return Err(eyre::eyre!("Invalid AVS type: {}", s)),
        })
    }
}

impl From<AvsType> for AVSType {
    fn from(val: AvsType) -> Self {
        match val {
            AvsType::Validator => AVSType::VALIDATOR,
            AvsType::Underwriter => AVSType::UNDERWRITER,
        }
    }
}

#[derive(Debug, Parser)]
pub struct OperatorInfoCommand {
    /// The RPC URL of the Ethereum node
    #[clap(long, env = "EXECUTION_RPC_URL")]
    execution_rpc_url: String,

    /// Operator address to query
    #[clap(long)]
    operator_address: Address,

    /// ProposerRegistry contract address
    #[clap(long)]
    proposer_registry_address: Address,

    /// AVSType
    #[clap(long, value_parser = AvsType::from_str)]
    avs_type: AvsType,
}

impl OperatorInfoCommand {
    pub async fn execute(&self) -> Result<()> {
        let provider = ProviderBuilder::new().on_http(Url::from_str(&self.execution_rpc_url)?);

        let registry = ProposerRegistry::new(self.proposer_registry_address, provider);

        let avs_type = self.avs_type.into();

        let operator_info = registry.operatorInfo(self.operator_address, avs_type).call().await?;

        info!("Operator: {}", self.operator_address);
        info!("Public Key: 0x{}", hex::encode(&operator_info.pubKey));
        info!("Is Active: {}", operator_info.isActive);

        Ok(())
    }
}
