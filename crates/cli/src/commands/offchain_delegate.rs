use std::time::Duration;

use alloy::signers::k256::sha2::{Digest, Sha256};
use clap::{Parser, ValueEnum};
use eyre::Result;
use reqwest::Url;
use serde::Serialize;
use taiyi_crypto::bls::{
    serialize_bls_publickey, serialize_bls_signature, PublicKey as BlsPublicKey,
    Signature as BlsSignature,
};
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
    /// underwriter BLS public key
    #[clap(long, env = "UNDERWRITER_PUBKEY")]
    pub underwriter_pubkey: String,
    /// The action to perform, delegate or revoke
    #[clap(long, env = "ACTION", default_value = "delegate")]
    pub action: Action,
    /// The source of the private key.
    #[clap(subcommand)]
    pub source: KeySource,

    #[clap(long, env = "FORK_VERSION", value_parser = parse_fork_version)]
    pub fork_version: [u8; 4],
}

fn parse_fork_version(s: &str) -> Result<[u8; 4], hex::FromHexError> {
    // Remove "0x" prefix if present
    let cleaned = s.trim_start_matches("0x");
    let decoded = hex::decode(cleaned)?;
    if decoded.len() != 4 {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    let mut res = [0; 4];
    res.copy_from_slice(&decoded);
    Ok(res)
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
                let underwriter_pubkey = parse_bls_public_key(&self.underwriter_pubkey)?;
                let signed_messages = generate_from_local_keys(
                    secret_keys
                        .iter()
                        .map(|s| {
                            hex::decode(s)
                                .map_err(|e| eyre::eyre!("Failed to decode secret key: {}", e))
                        })
                        .collect::<Result<Vec<Vec<u8>>>>()?,
                    underwriter_pubkey,
                    self.fork_version,
                    self.action.clone(),
                )?;
                debug!("Signed {} messages with local keys", signed_messages.len());

                signed_messages
            }
            KeySource::LocalKeystore { opts } => {
                let keystore_secret = KeystoreSecret::from_keystore_options(opts)?;
                let underwriter_pubkey = parse_bls_public_key(&self.underwriter_pubkey)?;
                let signed_messages = generate_from_keystore(
                    &opts.path,
                    keystore_secret,
                    underwriter_pubkey,
                    self.fork_version,
                    self.action.clone(),
                )?;
                debug!("Signed {} messages with keystore", signed_messages.len());

                signed_messages
            }
            KeySource::Dirk { opts } => {
                let mut dirk =
                    Dirk::connect(opts.url.clone(), opts.tls_credentials.clone()).await?;

                let underwriter_pubkey = parse_bls_public_key(&self.underwriter_pubkey)?;
                let signed_messages = generate_from_dirk(
                    &mut dirk,
                    underwriter_pubkey,
                    opts.wallet_path.clone(),
                    opts.passphrases.clone(),
                    self.fork_version,
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
    /// Signal delegation of a validator pubkey to a underwriter pubkey.
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
    #[serde(serialize_with = "serialize_bls_signature")]
    //, deserialize_with = "deserialize_bls_signature")]
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DelegationMessage {
    action: u8,
    #[serde(serialize_with = "serialize_bls_publickey")]
    pub validator_pubkey: BlsPublicKey,
    #[serde(serialize_with = "serialize_bls_publickey")]
    pub delegatee_pubkey: BlsPublicKey,
}

impl DelegationMessage {
    /// Create a new delegation message.
    pub fn new(validator_pubkey: BlsPublicKey, underwriter_pubkey: BlsPublicKey) -> Self {
        Self {
            action: SignedMessageAction::Delegation as u8,
            validator_pubkey,
            delegatee_pubkey: underwriter_pubkey,
        }
    }

    /// Compute the digest of the delegation message.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([self.action]);
        hasher.update(self.validator_pubkey.compress());
        hasher.update(self.delegatee_pubkey.compress());
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SignedRevocation {
    pub message: RevocationMessage,
    #[serde(serialize_with = "serialize_bls_signature")]
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RevocationMessage {
    action: u8,
    #[serde(serialize_with = "serialize_bls_publickey")]
    pub validator_pubkey: BlsPublicKey,
    #[serde(serialize_with = "serialize_bls_publickey")]
    pub underwriter_pubkey: BlsPublicKey,
}

impl RevocationMessage {
    /// Create a new revocation message.
    pub fn new(validator_pubkey: BlsPublicKey, underwriter_pubkey: BlsPublicKey) -> Self {
        Self { action: SignedMessageAction::Revocation as u8, validator_pubkey, underwriter_pubkey }
    }

    /// Compute the digest of the revocation message.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([self.action]);
        hasher.update(self.validator_pubkey.compress());
        hasher.update(self.underwriter_pubkey.compress());
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use taiyi_crypto::bls::PublicKey as BlsPublicKey;

    use crate::commands::offchain_delegate::parse_fork_version;

    use super::{DelegationMessage, RevocationMessage};

    #[test]
    fn test_delegation_message_digest() {
        let validator_pubkey = BlsPublicKey::from_bytes(
            &hex::decode("a28647210f27b88486b3f79ebbac5f6da5cd3ab986d5d3d56d44caf538c17f010b04cb1c6f7676f8cd02937fb2753a16")
                .unwrap(),
        )
        .unwrap();
        let underwriter_pubkey = BlsPublicKey::from_bytes(
            &hex::decode("a28647210f27b88486b3f79ebbac5f6da5cd3ab986d5d3d56d44caf538c17f010b04cb1c6f7676f8cd02937fb2753a16")
                .unwrap(),
        )
        .unwrap();
        let message = DelegationMessage::new(validator_pubkey, underwriter_pubkey);
        let digest = message.digest();
        assert_eq!(
            digest,
            [
                226, 222, 227, 110, 50, 243, 244, 144, 139, 145, 232, 236, 80, 207, 211, 53, 23,
                23, 47, 128, 152, 143, 22, 54, 108, 184, 176, 3, 30, 30, 25, 86
            ]
        );
    }

    #[test]
    fn test_revocation_message_digest() {
        let validator_pubkey = BlsPublicKey::from_bytes(
            &hex::decode("a28647210f27b88486b3f79ebbac5f6da5cd3ab986d5d3d56d44caf538c17f010b04cb1c6f7676f8cd02937fb2753a16")
                .unwrap(),
        )
        .unwrap();
        let underwriter_pubkey = BlsPublicKey::from_bytes(
            &hex::decode("a28647210f27b88486b3f79ebbac5f6da5cd3ab986d5d3d56d44caf538c17f010b04cb1c6f7676f8cd02937fb2753a16")
                .unwrap(),
        )
        .unwrap();
        let message = RevocationMessage::new(validator_pubkey, underwriter_pubkey);
        let digest = message.digest();
        assert_eq!(
            digest,
            [
                84, 104, 200, 42, 91, 64, 136, 102, 191, 97, 15, 88, 26, 22, 201, 239, 235, 15,
                119, 36, 227, 113, 49, 218, 35, 166, 197, 105, 45, 76, 150, 200
            ]
        );
    }

    #[test]
    fn test_parse_fork_version() {
        let fork_version = parse_fork_version("0x10000910").unwrap();
        assert_eq!(fork_version, [16, 0, 9, 16]);
    }
}
