// codes are basically copied from https://github.com/chainbound/bolt/blob/89253d92b079adf0abf6c9279eeed1d5dc7a3aed/bolt-cli/src/common/keystore.rs
use alloy::primitives::B256;
use clap::Parser;
use eth2_keystore::Keystore;
use eyre::{bail, Result};
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Debug, Error)]
pub enum BlstError {
    #[error("Deserialization failed: {msg}")]
    Deserialize { msg: String },
}

use crate::{
    commands::offchain_delegate::{
        Action, DelegationMessage, RevocationMessage, SignedDelegation, SignedMessage,
        SignedRevocation,
    },
    keys_management::{
        dirk::{Dirk, DirkOpts},
        keystore::{keystore_paths, KeystoreError, KeystoreSecret, LocalKeystoreOpts},
        signing::{compute_commit_boost_signing_root, compute_domain_from_mask},
    },
};
use taiyi_crypto::bls::{
    PublicKey as BlsPublicKey, SecretKey as BlsSecretKey, Signature as BlsSignature,
};

#[derive(Debug, Clone, Parser)]
pub enum KeySource {
    /// Use local secret keys to generate the signed messages.
    SecretKeys {
        /// The private key in hex format.
        /// Multiple secret keys must be separated by commas.
        #[clap(long, env = "SECRET_KEYS", value_delimiter = ',', hide_env_values = true)]
        secret_keys: Vec<String>,
    },

    /// Use an EIP-2335 filesystem keystore directory to generate the signed messages.
    LocalKeystore {
        /// The options for reading the keystore directory.
        #[clap(flatten)]
        opts: LocalKeystoreOpts,
    },

    /// Use a remote DIRK keystore to generate the signed messages.
    Dirk {
        /// The options for connecting to the DIRK keystore.
        #[clap(flatten)]
        opts: DirkOpts,
    },
}

/// Generate signed delegations/revocations using local BLS private keys
///
/// - Use the provided private keys from either CLI or env variable
/// - Create message
/// - Compute the signing roots and sign the messages
/// - Return the signed messages
pub fn generate_from_local_keys(
    secret_keys: &[String],
    underwriter_pubkey: BlsPublicKey,
    fork_version: [u8; 4],
    action: Action,
) -> Result<Vec<SignedMessage>> {
    let mut signed_messages = Vec::with_capacity(secret_keys.len());

    for sk in secret_keys {
        let sk = BlsSecretKey::deserialize(sk.as_ref())
            .map_err(|err| BlstError::Deserialize { msg: format!("{:?}", err) })?;
        match action {
            Action::Delegate => {
                let message = DelegationMessage::new(sk.sk_to_pk(), underwriter_pubkey);
                let signing_root =
                    compute_commit_boost_signing_root(message.digest(), fork_version)?;
                let signature = sk.sign(signing_root.0.as_ref(), &[], &[]);
                let signed = SignedDelegation { message, signature };
                signed_messages.push(SignedMessage::Delegation(signed))
            }
            Action::Revoke => {
                let message = RevocationMessage::new(sk.sk_to_pk(), underwriter_pubkey);
                let signing_root =
                    compute_commit_boost_signing_root(message.digest(), fork_version)?;
                let signature = sk.sign(signing_root.0.as_ref(), &[], &[]);
                let signed = SignedRevocation { message, signature };
                signed_messages.push(SignedMessage::Revocation(signed));
            }
        }
    }

    Ok(signed_messages)
}

/// Generate signed delegations/revocations using a keystore file
///
/// - Read the keystore file
/// - Decrypt the keypairs using the password
/// - Create messages
/// - Compute the signing roots and sign the message
/// - Return the signed message
pub fn generate_from_keystore(
    keys_path: &str,
    keystore_secret: KeystoreSecret,
    underwriter_pubkey: BlsPublicKey,
    fork_version: [u8; 4],
    action: Action,
) -> Result<Vec<SignedMessage>> {
    let keystores_paths = keystore_paths(keys_path)?;
    let mut signed_messages = Vec::with_capacity(keystores_paths.len());
    debug!("Found {} keys in the keystore", keystores_paths.len());

    for path in keystores_paths {
        let ks = Keystore::from_json_file(path).map_err(KeystoreError::Eth2Keystore)?;
        let password = keystore_secret.get(ks.pubkey()).ok_or(KeystoreError::MissingPassword)?;
        let kp = ks.decrypt_keypair(password.as_bytes()).map_err(KeystoreError::Eth2Keystore)?;
        let validator_pubkey = BlsPublicKey::deserialize(kp.pk.serialize().to_vec().as_ref())
            .map_err(|err| BlstError::Deserialize { msg: format!("{:?}", err) })?;
        let validator_private_key = kp.sk;

        match action {
            Action::Delegate => {
                let message = DelegationMessage::new(validator_pubkey, underwriter_pubkey);
                let signing_root =
                    compute_commit_boost_signing_root(message.digest(), fork_version)?;
                let signature = validator_private_key.sign(signing_root.0.into());
                let signed = SignedDelegation {
                    message,
                    signature: BlsSignature::deserialize(&signature.serialize())
                        .map_err(|err| BlstError::Deserialize { msg: format!("{:?}", err) })?,
                };
                signed_messages.push(SignedMessage::Delegation(signed));
            }
            Action::Revoke => {
                let message = RevocationMessage::new(validator_pubkey, underwriter_pubkey);
                let signing_root =
                    compute_commit_boost_signing_root(message.digest(), fork_version)?;
                let signature = validator_private_key.sign(signing_root.0.into());
                let signed = SignedRevocation {
                    message,
                    signature: BlsSignature::deserialize(&signature.serialize())
                        .map_err(|err| BlstError::Deserialize { msg: format!("{:?}", err) })?,
                };
                signed_messages.push(SignedMessage::Revocation(signed));
            }
        }
    }

    Ok(signed_messages)
}

/// Generate signed delegations/revocations using a remote Dirk signer
pub async fn generate_from_dirk(
    dirk: &mut Dirk,
    underwriter_pubkey: BlsPublicKey,
    account_path: String,
    passphrases: Option<Vec<String>>,
    fork_version: [u8; 4],
    action: Action,
) -> Result<Vec<SignedMessage>> {
    // first read the accounts from the remote keystore
    let accounts = dirk.list_accounts(account_path).await?;
    debug!("Found {} remote accounts to sign with", accounts.len());

    let mut signed_messages = Vec::with_capacity(accounts.len());

    // specify the signing domain (needs to be included in the signing request)
    let domain = B256::from(compute_domain_from_mask(fork_version));

    for account in accounts {
        // for each available pubkey we control, sign a delegation message
        let pubkey = BlsPublicKey::deserialize(account.public_key.as_slice()).expect("bls error");

        // Note: before signing, we must unlock the account
        let mut is_unlocked = false;
        if let Some(ref passphrases) = passphrases {
            for passphrase in passphrases {
                if dirk.unlock_account(account.name.clone(), passphrase.clone()).await? {
                    is_unlocked = true;
                    break;
                }
            }
            if !is_unlocked {
                bail!("Failed to unlock account {} with provided passphrases", account.name);
            }
        } else {
            bail!("A passphrase is required in order to sign messages remotely with Dirk");
        }

        match action {
            Action::Delegate => {
                let message = DelegationMessage::new(pubkey, underwriter_pubkey);
                let signing_root = message.digest().into(); // Dirk does the hash tree root internally
                let signature = dirk.request_signature(&account, signing_root, domain).await?;
                let signed = SignedDelegation { message, signature };
                signed_messages.push(SignedMessage::Delegation(signed));
            }
            Action::Revoke => {
                let message = RevocationMessage::new(pubkey, underwriter_pubkey);
                let signing_root = message.digest().into(); // Dirk does the hash tree root internally
                let signature = dirk.request_signature(&account, signing_root, domain).await?;
                let signed = SignedRevocation { message, signature };
                signed_messages.push(SignedMessage::Revocation(signed));
            }
        }

        // Try to lock the account back after signing
        if let Err(err) = dirk.lock_account(account.name.clone()).await {
            warn!("Failed to lock account after signing {}: {:?}", account.name, err);
        }
    }

    Ok(signed_messages)
}
