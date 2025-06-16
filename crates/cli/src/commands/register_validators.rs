use std::str::FromStr;

use alloy_network::EthereumWallet;
use alloy_primitives::{Address, U256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolValue;
use clap::Parser;
use eyre::Result;
use eth2_keystore::Keystore;
use reqwest::Url;
use taiyi_contracts::{SignedRegistration, TaiyiMiddleware};
use taiyi_crypto::{sign, to_public_key};
use tracing::{debug, info};

use crate::{
    keys_management::keystore::{keystore_paths, KeystoreError, KeystoreSecret},
    keysource::KeySource,
};

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

    /// Operator address
    #[clap(long, env = "OPERATOR_ADDRESS")]
    operator_address: Address,

    /// Value of the transaction
    #[clap(long, env = "COLLATERAL")]
    collateral: U256,

    /// The source of the private key.
    #[clap(subcommand)]
    source: KeySource,
}

impl RegisterValidatorsCommand {
    pub async fn execute(&self) -> Result<()> {
        // Setup provider and signer
        let signer: PrivateKeySigner = self.private_key.parse()?;
        let wallet = EthereumWallet::new(signer.clone());
        let provider = ProviderBuilder::new()
            .wallet(wallet.clone())
            .on_http(Url::from_str(&self.execution_rpc_url)?);

        let bls_signatures = match &self.source {
            KeySource::SecretKeys { secret_keys } => secret_keys
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
                .collect::<Result<Vec<_>>>()?,
            KeySource::LocalKeystore { opts } => {
                let keystore_secret = KeystoreSecret::from_keystore_options(opts)?;
                generate_signed_registrations_from_keystore(
                    &opts.path,
                    keystore_secret,
                    self.operator_address,
                )?
            }
            KeySource::Dirk { .. } => {
                unimplemented!("Dirk is not supported yet");
            }
        };

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
pub fn generate_signed_registrations_from_keystore(
    keys_path: &str,
    keystore_secret: KeystoreSecret,
    operator_address: Address,
) -> Result<Vec<SignedRegistration>> {
    let keystores_paths = keystore_paths(keys_path)?;
    let mut signed_messages = Vec::with_capacity(keystores_paths.len());
    debug!("Found {} keys in the keystore", keystores_paths.len());

    for path in keystores_paths {
        let ks = Keystore::from_json_file(path).map_err(KeystoreError::Eth2Keystore)?;
        let password = keystore_secret.get(ks.pubkey()).ok_or(KeystoreError::MissingPassword)?;
        let kp = ks.decrypt_keypair(password.as_bytes()).map_err(KeystoreError::Eth2Keystore)?;
        let sk = U256::from_be_slice(kp.sk.serialize().as_bytes());
        let validator_pubkey = to_public_key(sk)?;
        let message = operator_address.abi_encode();
        let sig = sign(sk, &message, &DOMAIN_SEPARATOR)?;
        let signed = SignedRegistration { pubkey: validator_pubkey, signature: sig };
        signed_messages.push(signed);
    }
    Ok(signed_messages)
}
