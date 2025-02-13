use alloy_network::EthereumWallet;
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use clap::Parser;
use taiyi_contracts::{
    AVSDirectory, SignatureWithSaltAndExpiry, TaiyiValidatorAVSEigenlayerMiddleware,
};
use tracing::info;

#[derive(Debug, Parser)]
pub struct RegisterValidatorAVSCommand {
    /// rpc url
    #[clap(long, env = "EXECUTION_RPC_URL")]
    pub execution_rpc_url: String,

    /// Private key in hex format
    #[clap(long, env = "PRIVATE_KEY")]
    pub private_key: String,

    #[clap(long, env = "SALT")]
    pub salt: B256,

    #[clap(long, env = "AVS_DIRECTORY_ADDRESS")]
    pub avs_directory_address: Address,

    #[clap(long, env = "TAIYI_AVS_ADDRESS")]
    pub taiyi_avs_address: Address,
}

impl RegisterValidatorAVSCommand {
    pub async fn execute(&self) -> eyre::Result<()> {
        // Create a wallet from the private key
        let signer: PrivateKeySigner = self.private_key.parse()?;
        let operator = signer.address();
        // Connect to the Ethereum network
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(EthereumWallet::new(signer.clone()))
            .on_builtin(&self.execution_rpc_url)
            .await?;

        let taiyi_eigenlayer_contract =
            TaiyiValidatorAVSEigenlayerMiddleware::new(self.taiyi_avs_address, provider.clone());

        let avs_directory_contract =
            AVSDirectory::new(self.avs_directory_address, provider.clone());

        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
        let expiry = now + std::time::Duration::from_secs(30 * 60);
        let expiry = U256::from(expiry.as_secs());

        let signature_digest_hash = avs_directory_contract
            .calculateOperatorAVSRegistrationDigestHash(
                signer.address(),
                self.taiyi_avs_address,
                self.salt,
                expiry,
            )
            .call()
            .await?
            ._0;
        let signature = Bytes::from(signer.sign_hash_sync(&signature_digest_hash)?.as_bytes());
        let signature_entry = SignatureWithSaltAndExpiry { signature, expiry, salt: self.salt };

        let tx = taiyi_eigenlayer_contract
            .registerOperatorToAVS(operator, signature_entry)
            .into_transaction_request();

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
