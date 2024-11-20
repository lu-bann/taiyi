use std::str::FromStr;

use alloy_network::EthereumWallet;
use alloy_primitives::{Address, Bytes};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use clap::Parser;
use tracing::info;
use ProposerRegistry::ProposerRegistryInstance;

#[derive(Debug, Parser)]
pub struct RegisterCommand {
    /// rpc url
    #[clap(long = "rpc_url")]
    pub rpc_url: String,

    /// Private key in hex format
    #[clap(long = "private_key")]
    pub private_key: String,

    /// taiyi proposer registry contract address
    #[clap(long = "taiyi_proposer_registry_contract_addr")]
    pub taiyi_proposer_registry_contract_addr: String,

    #[clap(long = "proposer_pubkey")]
    pub proposer_pubkey: String,
}

sol! {

    #[sol(rpc)]
    contract ProposerRegistry {
        #[derive(Debug)]
        function registerValidator(bytes calldata pubkey);
    }
}

impl RegisterCommand {
    pub async fn execute(&self) -> eyre::Result<()> {
        // Create a wallet from the private key
        let signer: PrivateKeySigner = self.private_key.parse()?;
        // Connect to the Ethereum network
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(EthereumWallet::new(signer.clone()))
            .on_builtin(&self.rpc_url)
            .await?;

        // Parse contract address
        let proposer_registry_address: Address =
            self.taiyi_proposer_registry_contract_addr.parse()?;
        let proposer_registry =
            ProposerRegistryInstance::new(proposer_registry_address, provider.clone());

        let proposer_pubkey = Bytes::from_str(&self.proposer_pubkey)?;

        // Call deposit function
        let tx = proposer_registry.registerValidator(proposer_pubkey).into_transaction_request();

        let pending_tx = provider.send_transaction(tx).await?;

        info!(
            "Register validator to proposer registry Transaction sent: {:?}",
            pending_tx.tx_hash()
        );

        // Wait for transaction to be mined
        let receipt = pending_tx.get_receipt().await?;
        info!(
            "Register validator to proposer registry Transaction mined in block: {:?}",
            receipt.block_number
        );
        Ok(())
    }
}
