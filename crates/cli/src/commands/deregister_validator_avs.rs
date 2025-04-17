use std::str::FromStr;

use alloy_network::EthereumWallet;
use alloy_primitives::Address;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use clap::Parser;
use eyre::Result;
use reqwest::Url;
use taiyi_contracts::TaiyiValidatorAVSEigenlayerMiddleware;
use tracing::info;

#[derive(Debug, Parser)]
pub struct DeregisterValidatorAVSCommand {
    /// rpc url
    #[clap(long, env = "EXECUTION_RPC_URL")]
    pub execution_rpc_url: String,

    /// Private key in hex format
    #[clap(long, env = "PRIVATE_KEY")]
    pub private_key: String,

    #[clap(long, env = "TAIYI_EIGENLAYER_MIDDLEWARE_ADDRESS")]
    pub taiyi_eigenlayer_middleware_address: Address,
}

impl DeregisterValidatorAVSCommand {
    pub async fn execute(&self) -> Result<()> {
        // Create a wallet from the private key
        let signer: PrivateKeySigner = self.private_key.parse()?;
        // Connect to the Ethereum network
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::new(signer.clone()))
            .on_http(Url::from_str(&self.execution_rpc_url)?);

        let taiyi_eigenlayer_contract = TaiyiValidatorAVSEigenlayerMiddleware::new(
            self.taiyi_eigenlayer_middleware_address,
            provider.clone(),
        );

        let tx = taiyi_eigenlayer_contract.deregisterOperator().into_transaction_request();

        let pending_tx = provider.send_transaction(tx).await?;

        info!("Deregister operator transaction sent: {:?}", pending_tx.tx_hash());

        // Wait for transaction to be mined
        let receipt = pending_tx.get_receipt().await?;
        info!("Deregister operator transaction mined in block: {:?}", receipt.block_number);

        Ok(())
    }
}
