use std::str::FromStr;

use alloy_network::EthereumWallet;
use alloy_primitives::Address;
use alloy_provider::ProviderBuilder;
use alloy_signer_local::PrivateKeySigner;
use clap::Parser;
use eyre::Result;
use reqwest::Url;
use taiyi_contracts::AllocationManager;
use tracing::info;

#[derive(Debug, Parser)]
pub struct RegisterForOperatorSetsCommand {
    /// The RPC URL of the Ethereum node
    #[clap(long, env = "EXECUTION_RPC_URL")]
    execution_rpc_url: String,

    /// Tx signer private key
    #[clap(long, env = "PRIVATE_KEY")]
    private_key: String,

    /// Operator BLS key
    #[clap(long, env = "OPERATOR_BLS_KEY")]
    operator_bls_key: String,

    /// AVS address
    #[clap(long)]
    avs_address: Address,

    /// Allocation Manager contract address
    #[clap(long)]
    allocation_manager_address: Address,

    /// Operator set IDs (comma-separated list of uint32 values)
    #[clap(long, value_delimiter = ',')]
    operator_set_ids: Vec<u32>,

    /// Optional data to pass to the AVS (hex-encoded)
    #[clap(long, default_value = "0x")]
    data: String,
}

impl RegisterForOperatorSetsCommand {
    pub async fn execute(&self) -> Result<()> {
        let signer: PrivateKeySigner = self.private_key.parse()?;
        let operator_address = signer.address();
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::new(signer.clone()))
            .on_http(Url::from_str(&self.execution_rpc_url)?);

        let allocation_manager = AllocationManager::new(self.allocation_manager_address, provider);

        // Parse the data from hex
        let data = if self.data == "0x" || self.data.is_empty() {
            Vec::new()
        } else {
            hex::decode(self.data.trim_start_matches("0x"))?
        };

        // Create the RegisterParams struct
        let params = AllocationManager::RegisterParams {
            avs: self.avs_address,
            operatorSetIds: self.operator_set_ids.clone(),
            data: data.into(),
        };

        // Register the operator for the operator sets
        let tx =
            allocation_manager.registerForOperatorSets(operator_address, params).send().await?;

        info!("Transaction sent! Hash: {}", tx.tx_hash());
        info!(
            "Operator: {} registered for sets within AVS: {}",
            operator_address, self.avs_address
        );
        info!("Operator set IDs: {:?}", self.operator_set_ids);

        Ok(())
    }
}
