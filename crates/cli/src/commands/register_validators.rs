use std::str::FromStr;

use alloy_network::EthereumWallet;
use alloy_primitives::{Address, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolValue;
use clap::Parser;
use eyre::Result;
use reqwest::Url;
use taiyi_contracts::{SignedRegistration, TaiyiMiddleware};
use taiyi_crypto::{sign, to_public_key};
use tracing::info;

const DOMAIN_SEPARATOR: [u8; 4] = hex_literal::hex!("00555243"); // "URC" in little endian

#[derive(Debug, Parser)]
pub struct RegisterValidatorsCommand {
    /// The RPC URL of the Ethereum node
    #[clap(long, env = "EXECUTION_RPC_URL")]
    execution_rpc_url: String,

    /// Private key for signing transactions
    #[clap(long, env = "PRIVATE_KEY")]
    private_key: String,

    /// The EigenLayer Middleware contract address
    #[clap(long, env = "TAIYI_MIDDLEWARE_ADDRESS")]
    taiyi_middleware_address: Address,

    /// Private key for signing transactions
    #[clap(long, env = "BLS_PRIVATE_KEY", value_delimiter = ',')]
    bls_private_keys: Vec<String>,

    /// Operator address
    #[clap(long, env = "OPERATOR_ADDRESS")]
    operator_address: Address,

    /// Value of the transaction
    #[clap(long, env = "COLLATERAL")]
    collateral: U256,
}

impl RegisterValidatorsCommand {
    pub async fn execute(&self) -> Result<()> {
        // Setup provider and signer
        let signer: PrivateKeySigner = self.private_key.parse()?;
        let wallet = EthereumWallet::new(signer.clone());
        let provider = ProviderBuilder::new()
            .wallet(wallet.clone())
            .on_http(Url::from_str(&self.execution_rpc_url)?);

        let bls_signatures = self
            .bls_private_keys
            .clone()
            .into_iter()
            .map(|k| {
                let key_bytes = hex::decode(k)?;
                let sk = U256::from_be_slice(&key_bytes);
                let pubkey = to_public_key(sk)?;
                let message = self.operator_address.abi_encode();

                let sig = sign(sk, &message, &DOMAIN_SEPARATOR)?;
                Ok(SignedRegistration { pubkey, signature: sig })
            })
            .collect::<Result<Vec<_>>>()?;

        // Create middleware contract interface
        let middleware = TaiyiMiddleware::new(self.taiyi_middleware_address, provider.clone());

        let tx = middleware
            .registerValidators(bls_signatures)
            .into_transaction_request()
            .value(self.collateral);
        let res = provider.send_transaction(tx).await?;

        info!("Validators registered successfully! Transaction hash: {:?}", res.tx_hash());
        let receipt = res.get_receipt().await?;
        info!("Transaction receipt got. Confirmed in the block {:?}", receipt.block_number);
        Ok(())
    }
}
