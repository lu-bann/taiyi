use alloy_primitives::Address;
use alloy_provider::ProviderBuilder;
use clap::Parser;
use eyre::Result;
use taiyi_contracts::ProposerRegistry;
use tracing::info;

#[derive(Debug, Parser)]
pub struct GetValidatorsForOperatorsCommand {
    /// The RPC URL of the Ethereum node
    #[clap(long, env = "EXECUTION_RPC_URL")]
    execution_rpc_url: String,

    /// Operator address to query
    #[clap(long)]
    operator_address: Address,

    /// ProposerRegistry contract address
    #[clap(long)]
    proposer_registry_address: Address,
}

impl GetValidatorsForOperatorsCommand {
    pub async fn execute(&self) -> Result<()> {
        let provider = ProviderBuilder::new().on_builtin(&self.execution_rpc_url).await?;

        let registry = ProposerRegistry::new(self.proposer_registry_address, provider);

        let validators = registry.getValidatorsForOperator(self.operator_address).call().await?;

        info!("Operator: {}", self.operator_address);
        for (i, validator) in validators._0.into_iter().enumerate() {
            info!("Validator {}: 0x{}", i + 1, hex::encode(&validator));
        }

        Ok(())
    }
}
