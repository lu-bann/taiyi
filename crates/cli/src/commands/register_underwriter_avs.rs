use std::str::FromStr;

use alloy_network::EthereumWallet;
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_provider::ProviderBuilder;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use clap::Parser;
use hex::FromHex;
use reqwest::Url;
use taiyi_contracts::{
    AVSDirectory, SignatureWithSaltAndExpiry, TaiyiUnderwriterAVSEigenlayerMiddleware,
};
use tracing::info;

#[derive(Debug, Parser)]
pub struct RegisterUnderwriterAVSCommand {
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

    #[clap(long, env = "UNDERWRITER_AVS_ADDRESS")]
    pub underwriter_avs_address: Address,

    #[clap(long, env = "OPERATOR_BLS_KEY")]
    pub operator_bls_key: String,
}

impl RegisterUnderwriterAVSCommand {
    pub async fn execute(&self) -> eyre::Result<()> {
        // Create a wallet from the private key
        let signer: PrivateKeySigner = self.private_key.parse()?;
        let operator = signer.address();

        // Connect to the Ethereum network
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::new(signer.clone()))
            .on_http(Url::from_str(&self.execution_rpc_url)?);

        let underwriter_contract = TaiyiUnderwriterAVSEigenlayerMiddleware::new(
            self.underwriter_avs_address,
            provider.clone(),
        );
        let avs_directory_contract =
            AVSDirectory::new(self.avs_directory_address, provider.clone());

        // Create signature with expiry
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
        let expiry = now + std::time::Duration::from_secs(30 * 60);
        let expiry = U256::from(expiry.as_secs());

        let signature_digest_hash = avs_directory_contract
            .calculateOperatorAVSRegistrationDigestHash(
                operator,
                self.underwriter_avs_address,
                self.salt,
                expiry,
            )
            .call()
            .await?
            ._0;

        let signature = Bytes::from(signer.sign_hash_sync(&signature_digest_hash)?.as_bytes());
        let signature_entry = SignatureWithSaltAndExpiry { signature, expiry, salt: self.salt };

        // Parse BLS public key
        let operator_bls_key = Bytes::from_hex(&self.operator_bls_key)?;

        let tx = underwriter_contract
            .registerOperatorToAVSWithPubKey(operator, signature_entry, operator_bls_key)
            .send()
            .await?;

        info!("Register operator to underwriter Transaction sent: {:?}", tx.tx_hash());

        let receipt = tx.get_receipt().await?;
        info!(
            "Register operator to underwriter Transaction mined in block: {:?}",
            receipt.block_number
        );

        Ok(())
    }
}
