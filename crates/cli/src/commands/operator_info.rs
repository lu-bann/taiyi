use std::str::FromStr;

use alloy_primitives::Address;
use alloy_provider::ProviderBuilder;
use clap::Parser;
use eyre::Result;
use reqwest::Url;
use taiyi_contracts::TaiyiCoordinator;
use tracing::info;

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
    linglong_coordinator_address: Address,
}

impl OperatorInfoCommand {
    pub async fn execute(&self) -> Result<()> {
        let provider = ProviderBuilder::new().connect_http(Url::from_str(&self.execution_rpc_url)?);

        let registry = TaiyiCoordinator::new(self.linglong_coordinator_address, provider);

        let operator_info = registry.getOperator(self.operator_address).call().await?;

        info!("Operator: {}, status: {:?}", self.operator_address, &operator_info.status);

        Ok(())
    }
}
