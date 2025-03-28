use alloy_network::EthereumWallet;
use alloy_primitives::{Address, Bytes};
use alloy_provider::ProviderBuilder;
use alloy_signer_local::PrivateKeySigner;
use clap::Parser;
use eyre::Result;
use hex::FromHex;
use taiyi_contracts::TaiyiValidatorAVSEigenlayerMiddleware;
use tracing::info;

#[derive(Debug, Parser)]
pub struct RegisterValidatorsCommand {
    /// The RPC URL of the Ethereum node
    #[clap(long, env = "EXECUTION_RPC_URL")]
    execution_rpc_url: String,

    /// Private key for signing transactions
    #[clap(long, env = "PRIVATE_KEY")]
    private_key: String,

    /// The EigenLayer Middleware contract address
    #[clap(long, env = "TAIYI_VALIDATOR_AVS_ADDRESS")]
    taiyi_validator_avs_address: Address,

    /// Comma-separated list of validator public keys in hex format
    #[clap(long, env = "VALIDATOR_PUBKEYS", value_delimiter = ',')]
    validator_pubkeys: Vec<String>,

    /// Comma-separated list of pod owner addresses
    #[clap(long, env = "POD_OWNERS", value_delimiter = ',')]
    pod_owners: Vec<String>,

    /// Comma-separated list of delegated underwriters in hex format
    #[clap(long, env = "DELEGATED_UNDERWRITERS", value_delimiter = ',')]
    delegated_underwriters: Vec<String>,
}

impl RegisterValidatorsCommand {
    pub async fn execute(&self) -> Result<()> {
        // Setup provider and signer
        let signer: PrivateKeySigner = self.private_key.parse()?;
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(EthereumWallet::new(signer.clone()))
            .on_builtin(&self.execution_rpc_url)
            .await?;

        // Parse validator pubkeys into Vec<Vec<u8>>
        let val_pub_keys: Vec<Vec<Bytes>> = self
            .validator_pubkeys
            .iter()
            .map(|key| {
                vec![Bytes::from_hex(key.trim())
                    .unwrap_or_else(|_| panic!("Invalid hex string {key:} for validator pubkey"))]
            })
            .collect();

        // Parse pod owners into Vec<Address>
        let pod_owners: Vec<Address> = self
            .pod_owners
            .iter()
            .map(|addr| {
                addr.trim()
                    .parse::<Address>()
                    .unwrap_or_else(|_| panic!("Invalid address {addr:} for pod owner"))
            })
            .collect();

        // Parse delegated underwriters into Vec<Bytes>
        let delegated_underwriters: Vec<Bytes> = self
            .delegated_underwriters
            .iter()
            .map(|underwriter| {
                Bytes::from_hex(underwriter.trim()).unwrap_or_else(|_| {
                    panic!("Invalid hex string {underwriter:} for delegated underwriter")
                })
            })
            .collect();

        // Create middleware contract interface
        let middleware = TaiyiValidatorAVSEigenlayerMiddleware::new(
            self.taiyi_validator_avs_address,
            provider.clone(),
        );

        // Register validators
        let tx = middleware
            .registerValidators(val_pub_keys, pod_owners, delegated_underwriters)
            .send()
            .await?;

        info!("Registering validators with tx hash: {}", tx.tx_hash());

        let receipt = tx.get_receipt().await?;
        info!(
            "Validators registered successfully! Transaction hash: {:?}",
            receipt.transaction_hash
        );

        Ok(())
    }
}
