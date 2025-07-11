use std::str::FromStr;

use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use clap::Parser;
use eyre::Result;
use reqwest::Url;
use taiyi_contracts::TaiyiMiddleware;
use tracing::info;

#[derive(Debug, Parser)]
pub struct GetStrategiesStakesCommand {
    /// The RPC URL of the Ethereum node
    #[clap(long, env = "EXECUTION_RPC_URL")]
    execution_rpc_url: String,

    /// Operator address to query
    #[clap(long)]
    operator_address: Address,

    /// Validator AVS contract address
    #[clap(long)]
    validator_avs_address: Address,
}

impl GetStrategiesStakesCommand {
    pub async fn execute(&self) -> Result<()> {
        let provider = ProviderBuilder::new().connect_http(Url::from_str(&self.execution_rpc_url)?);

        let avs = TaiyiMiddleware::new(self.validator_avs_address, provider);

        let result = avs.getStrategiesAndStakes(self.operator_address).call().await?;

        info!("Operator: {}", self.operator_address);
        for (strategy, stake) in result.strategyAddresses.into_iter().zip(result.stakeAmounts) {
            info!("Strategy: {}, Stake: {}", strategy, stake);
        }

        Ok(())
    }
}
