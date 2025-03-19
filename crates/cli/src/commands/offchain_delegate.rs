use std::time::Duration;

use alloy_signer::k256::sha2::{Digest, Sha256};
use clap::{Parser, ValueEnum};
use ethereum_consensus::{
    crypto::{PublicKey as BlsPublicKey, Signature as BlsSignature},
    networks::Network,
};
use eyre::Result;
use reqwest::Url;
use serde::Serialize;
use tracing::{debug, error, info};

use crate::{
    keys_management::{dirk::Dirk, keystore::KeystoreSecret, signing::parse_bls_public_key},
    keysource::{generate_from_dirk, generate_from_keystore, generate_from_local_keys, KeySource},
};

const RELAY_DELEGATE_PATH: &str = "/constraints/v1/builder/delegate";
const RELAY_REVOKE_PATH: &str = "/constraints/v1/builder/revoke";

#[derive(Debug, Parser)]
pub struct DelegateCommand {
    /// Relay url
    #[clap(long, env = "RELAY_URL")]
    pub relay_url: Url,
    /// Relay request timeout
    #[clap(long, env = "RELAY_REQUEST_TIMEOUT", default_value = "30")]
    pub relay_request_timeout: u64,
    /// Preconfer BLS public key
    #[clap(long, env = "GATEWAY_PUBKEY")]
    pub gateway_pubkey: String,
    /// Chain Network
    #[clap(long, env = "NETWORK", default_value = "mainnet")]
    pub network: Network,
    /// The action to perform, delegate or revoke
    #[clap(long, env = "ACTION", default_value = "delegate")]
    pub action: Action,
    /// The source of the private key.
    #[clap(subcommand)]
    pub source: KeySource,
}

#[derive(Debug, Clone, ValueEnum)]
#[clap(rename_all = "kebab_case")]
pub enum Action {
    Delegate,
    Revoke,
}

impl DelegateCommand {
    pub async fn execute(&self) -> Result<()> {
        let signed_messages = match &self.source {
            KeySource::SecretKeys { secret_keys } => {
                let preconfer_pubkey = parse_bls_public_key(&self.gateway_pubkey)?;
                let signed_messages = generate_from_local_keys(
                    secret_keys,
                    preconfer_pubkey,
                    self.network.clone(),
                    self.action.clone(),
                )?;
                debug!("Signed {} messages with local keys", signed_messages.len());

                signed_messages
            }
            KeySource::LocalKeystore { opts } => {
                let keystore_secret = KeystoreSecret::from_keystore_options(opts)?;
                let preconfer_pubkey = parse_bls_public_key(&self.gateway_pubkey)?;
                let signed_messages = generate_from_keystore(
                    &opts.path,
                    keystore_secret,
                    preconfer_pubkey,
                    self.network.clone(),
                    self.action.clone(),
                )?;
                debug!("Signed {} messages with keystore", signed_messages.len());

                signed_messages
            }
            KeySource::Dirk { opts } => {
                let mut dirk =
                    Dirk::connect(opts.url.clone(), opts.tls_credentials.clone()).await?;

                let preconfer_pubkey = parse_bls_public_key(&self.gateway_pubkey)?;
                let signed_messages = generate_from_dirk(
                    &mut dirk,
                    preconfer_pubkey,
                    opts.wallet_path.clone(),
                    opts.passphrases.clone(),
                    self.network.clone(),
                    self.action.clone(),
                )
                .await?;
                debug!("Signed {} messages with Dirk", signed_messages.len());

                signed_messages
            }
        };
        let request_url = self.relay_url.join(match self.action {
            Action::Delegate => RELAY_DELEGATE_PATH,
            Action::Revoke => RELAY_REVOKE_PATH,
        })?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.relay_request_timeout))
            .build()?;
        let response = client.post(request_url).json(&signed_messages).send().await?;
        if response.status().is_success() {
            info!("Successfully sent signed messages to relay");
        } else {
            let error_body = response.text().await?;
            error!("Failed to send signed messages to relay: {}", error_body);
        }

        Ok(())
    }
}

/// Event types that can be emitted by the validator pubkey to
/// signal some action to the relay.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum SignedMessageAction {
    /// Signal delegation of a validator pubkey to a preconfer pubkey.
    Delegation,
    /// Signal revocation of a previously delegated pubkey.
    Revocation,
}

/// Transparent serialization of signed messages.
/// This is used to serialize and deserialize signed messages
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum SignedMessage {
    Delegation(SignedDelegation),
    Revocation(SignedRevocation),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SignedDelegation {
    pub message: DelegationMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DelegationMessage {
    action: u8,
    pub validator_pubkey: BlsPublicKey,
    pub delegatee_pubkey: BlsPublicKey,
}

impl DelegationMessage {
    /// Create a new delegation message.
    pub fn new(validator_pubkey: BlsPublicKey, preconfer_pubkey: BlsPublicKey) -> Self {
        Self {
            action: SignedMessageAction::Delegation as u8,
            validator_pubkey,
            delegatee_pubkey: preconfer_pubkey,
        }
    }

    /// Compute the digest of the delegation message.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([self.action]);
        hasher.update(self.validator_pubkey.to_vec());
        hasher.update(self.delegatee_pubkey.to_vec());

        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SignedRevocation {
    pub message: RevocationMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RevocationMessage {
    action: u8,
    pub validator_pubkey: BlsPublicKey,
    pub preconfer_pubkey: BlsPublicKey,
}

impl RevocationMessage {
    /// Create a new revocation message.
    pub fn new(validator_pubkey: BlsPublicKey, preconfer_pubkey: BlsPublicKey) -> Self {
        Self { action: SignedMessageAction::Revocation as u8, validator_pubkey, preconfer_pubkey }
    }

    /// Compute the digest of the revocation message.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([self.action]);
        hasher.update(self.validator_pubkey.to_vec());
        hasher.update(self.preconfer_pubkey.to_vec());

        hasher.finalize().into()
    }
}
