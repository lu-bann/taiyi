// codes are basically copied from https://github.com/chainbound/bolt/blob/89253d92b079adf0abf6c9279eeed1d5dc7a3aed/bolt-cli/src/common/keystore.rs
use alloy::primitives::B256;
use alloy::rpc::types::beacon::constants::BLS_DST_SIG;
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
use taiyi_crypto::bls::{PublicKey as BlsPublicKey, SecretKey as BlsSecretKey};

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
    secret_keys: Vec<Vec<u8>>,
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
                let signature = sk.sign(signing_root.0.as_ref(), BLS_DST_SIG, &[]);
                let signed = SignedDelegation { message, signature };
                signed_messages.push(SignedMessage::Delegation(signed))
            }
            Action::Revoke => {
                let message = RevocationMessage::new(sk.sk_to_pk(), underwriter_pubkey);
                let signing_root =
                    compute_commit_boost_signing_root(message.digest(), fork_version)?;
                let signature = sk.sign(signing_root.0.as_ref(), BLS_DST_SIG, &[]);
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
        let validator_private_key = BlsSecretKey::deserialize(kp.sk.serialize().as_ref())
            .map_err(|err| BlstError::Deserialize { msg: format!("{:?}", err) })?;

        match action {
            Action::Delegate => {
                let message = DelegationMessage::new(validator_pubkey, underwriter_pubkey);
                let signing_root =
                    compute_commit_boost_signing_root(message.digest(), fork_version)?;
                let signature =
                    validator_private_key.sign(signing_root.0.as_ref(), BLS_DST_SIG, &[]);
                let signed = SignedDelegation { message, signature };
                signed_messages.push(SignedMessage::Delegation(signed));
            }
            Action::Revoke => {
                let message = RevocationMessage::new(validator_pubkey, underwriter_pubkey);
                let signing_root =
                    compute_commit_boost_signing_root(message.digest(), fork_version)?;
                let signature =
                    validator_private_key.sign(signing_root.0.as_ref(), BLS_DST_SIG, &[]);
                let signed = SignedRevocation { message, signature };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::offchain_delegate::Action;
    use crate::keys_management::keystore::KeystoreSecret;
    use bls::Keypair;
    use blst::BLST_ERROR;
    use eth2_keystore::KeystoreBuilder;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;

    // Helper function to create a temporary keystore directory with test keys
    fn create_temp_keystore_dir(num_keys: usize, password: &str) -> (PathBuf, Vec<String>) {
        let temp_dir = tempdir().unwrap();
        let keys_path = temp_dir.keep();
        let mut expected_pubkeys = Vec::new();

        for _ in 0..num_keys {
            // Generate a random keypair
            let keypair = Keypair::random();
            expected_pubkeys.push(hex::encode(keypair.pk.serialize()));

            // Create keystore directory for this key
            let key_dir = keys_path.join(format!("{}", keypair.pk.compress()));
            fs::create_dir_all(&key_dir).unwrap();
            println!("key_dir: {:?}", key_dir);

            // Build keystore
            let keystore = KeystoreBuilder::new(
                &keypair,
                password.as_bytes(),
                key_dir.to_str().unwrap().to_string(),
            )
            .unwrap()
            .build()
            .unwrap();
            println!("keystore: {:?}", keystore.path());
            keystore
                .to_json_writer(fs::File::create(key_dir.join("voting-keystore.json")).unwrap())
                .unwrap();
        }

        (keys_path, expected_pubkeys)
    }

    // Helper function to generate test BLS keys
    fn generate_test_secret_keys(count: usize) -> Vec<Vec<u8>> {
        let mut keys = Vec::new();
        for i in 0..count {
            let mut key_material = [0u8; 32];
            // Use the index to create unique key material
            key_material[31] = i as u8;
            key_material[30] = (i >> 8) as u8;
            key_material[29] = (i >> 16) as u8;
            key_material[28] = (i >> 24) as u8;
            let sk = BlsSecretKey::key_gen(&key_material, &[]).expect("bls key gen error");
            keys.push(sk.serialize().to_vec());
        }
        keys
    }

    // Helper function to generate a test underwriter public key
    fn generate_test_underwriter_pubkey() -> BlsPublicKey {
        let key_material = [1u8; 32]; // Use all 1s for underwriter key
        BlsSecretKey::key_gen(&key_material, &[]).unwrap().sk_to_pk()
    }

    #[test]
    fn test_generate_from_local_keys_delegate() {
        let secret_keys = generate_test_secret_keys(3);
        let underwriter_pubkey = generate_test_underwriter_pubkey();
        let fork_version = [0x01, 0x00, 0x00, 0x00];
        let action = Action::Delegate;

        let result =
            generate_from_local_keys(secret_keys.clone(), underwriter_pubkey, fork_version, action);

        assert!(result.is_ok(), "{}", result.unwrap_err().to_string());
        let signed_messages = result.unwrap();
        assert_eq!(signed_messages.len(), 3);

        for (i, signed_message) in signed_messages.iter().enumerate() {
            match signed_message {
                SignedMessage::Delegation(signed_delegation) => {
                    // Verify the message contains the correct validator pubkey
                    let expected_sk = BlsSecretKey::deserialize(&secret_keys[i]).unwrap();
                    let expected_pubkey = expected_sk.sk_to_pk();
                    assert_eq!(signed_delegation.message.validator_pubkey, expected_pubkey);
                    assert_eq!(signed_delegation.message.delegatee_pubkey, underwriter_pubkey);

                    // Verify the signature
                    let signing_root = compute_commit_boost_signing_root(
                        signed_delegation.message.digest(),
                        fork_version,
                    )
                    .unwrap();
                    let is_valid = signed_delegation.signature.verify(
                        false,
                        signing_root.0.as_ref(),
                        BLS_DST_SIG,
                        &[],
                        &expected_pubkey,
                        true,
                    );
                    assert!(
                        is_valid == BLST_ERROR::BLST_SUCCESS,
                        "Signature verification failed for delegation {}",
                        i
                    );
                }
                SignedMessage::Revocation(_) => panic!("Expected delegation, got revocation"),
            }
        }
    }

    #[test]
    fn test_generate_from_local_keys_revoke() {
        let secret_keys = generate_test_secret_keys(2);
        let underwriter_pubkey = generate_test_underwriter_pubkey();
        let fork_version = [0x01, 0x00, 0x00, 0x00];
        let action = Action::Revoke;

        let result =
            generate_from_local_keys(secret_keys.clone(), underwriter_pubkey, fork_version, action);

        assert!(result.is_ok());
        let signed_messages = result.unwrap();
        assert_eq!(signed_messages.len(), 2);

        for (i, signed_message) in signed_messages.iter().enumerate() {
            match signed_message {
                SignedMessage::Revocation(signed_revocation) => {
                    // Verify the message contains the correct validator pubkey
                    let expected_sk = BlsSecretKey::deserialize(&secret_keys[i]).unwrap();
                    let expected_pubkey = expected_sk.sk_to_pk();
                    assert_eq!(signed_revocation.message.validator_pubkey, expected_pubkey);
                    assert_eq!(signed_revocation.message.underwriter_pubkey, underwriter_pubkey);

                    // Verify the signature
                    let signing_root = compute_commit_boost_signing_root(
                        signed_revocation.message.digest(),
                        fork_version,
                    )
                    .unwrap();
                    let is_valid = signed_revocation.signature.verify(
                        false,
                        signing_root.0.as_ref(),
                        BLS_DST_SIG,
                        &[],
                        &expected_pubkey,
                        true,
                    );
                    assert!(
                        is_valid == BLST_ERROR::BLST_SUCCESS,
                        "Signature verification failed for revocation {}",
                        i
                    );
                }
                SignedMessage::Delegation(_) => panic!("Expected revocation, got delegation"),
            }
        }
    }

    #[test]
    fn test_generate_from_local_keys_single_key() {
        let secret_keys = generate_test_secret_keys(1);
        let underwriter_pubkey = generate_test_underwriter_pubkey();
        let fork_version = [0x01, 0x00, 0x00, 0x00];
        let action = Action::Delegate;

        let result =
            generate_from_local_keys(secret_keys, underwriter_pubkey, fork_version, action);

        assert!(result.is_ok());
        let signed_messages = result.unwrap();
        assert_eq!(signed_messages.len(), 1);
    }

    #[test]
    fn test_generate_from_local_keys_invalid_key() {
        let secret_keys = vec![b"invalid_key".to_vec()];
        let underwriter_pubkey = generate_test_underwriter_pubkey();
        let fork_version = [0x01, 0x00, 0x00, 0x00];
        let action = Action::Delegate;

        let result =
            generate_from_local_keys(secret_keys, underwriter_pubkey, fork_version, action);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("Deserialization failed"));
    }

    #[test]
    fn test_generate_from_local_keys_invalid_length_key() {
        let secret_keys = vec![vec![0xde, 0xad, 0xbe, 0xef]]; // Too short
        let underwriter_pubkey = generate_test_underwriter_pubkey();
        let fork_version = [0x01, 0x00, 0x00, 0x00];
        let action = Action::Delegate;

        let result =
            generate_from_local_keys(secret_keys, underwriter_pubkey, fork_version, action);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("Deserialization failed"));
    }

    #[test]
    fn test_generate_from_keystore_delegate() {
        let password = "test_password";
        let (keys_path, _expected_pubkeys) = create_temp_keystore_dir(3, password);
        let keystore_secret = KeystoreSecret::from_unique_password(password.to_string());
        let underwriter_pubkey = generate_test_underwriter_pubkey();
        let fork_version = [0x01, 0x00, 0x00, 0x00];
        let action = Action::Delegate;

        let result = generate_from_keystore(
            keys_path.to_str().unwrap(),
            keystore_secret,
            underwriter_pubkey,
            fork_version,
            action,
        );

        assert!(result.is_ok(), "{}", result.unwrap_err().to_string());
        let signed_messages = result.unwrap();
        assert_eq!(signed_messages.len(), 3);

        for signed_message in signed_messages {
            match signed_message {
                SignedMessage::Delegation(signed_delegation) => {
                    assert_eq!(signed_delegation.message.delegatee_pubkey, underwriter_pubkey);
                }
                SignedMessage::Revocation(_) => panic!("Expected delegation, got revocation"),
            }
        }
    }

    #[test]
    fn test_generate_from_keystore_revoke() {
        let password = "test_password";
        let (keys_path, _expected_pubkeys) = create_temp_keystore_dir(2, password);
        let keystore_secret = KeystoreSecret::from_unique_password(password.to_string());
        let underwriter_pubkey = generate_test_underwriter_pubkey();
        let fork_version = [0x01, 0x00, 0x00, 0x00];
        let action = Action::Revoke;

        let result = generate_from_keystore(
            keys_path.to_str().unwrap(),
            keystore_secret,
            underwriter_pubkey,
            fork_version,
            action,
        );

        assert!(result.is_ok());
        let signed_messages = result.unwrap();
        assert_eq!(signed_messages.len(), 2);

        for signed_message in signed_messages {
            match signed_message {
                SignedMessage::Revocation(signed_revocation) => {
                    assert_eq!(signed_revocation.message.underwriter_pubkey, underwriter_pubkey);
                }
                SignedMessage::Delegation(_) => panic!("Expected revocation, got delegation"),
            }
        }
    }

    #[test]
    fn test_generate_from_keystore_single_key() {
        let password = "test_password";
        let (keys_path, _expected_pubkeys) = create_temp_keystore_dir(1, password);
        let keystore_secret = KeystoreSecret::from_unique_password(password.to_string());
        let underwriter_pubkey = generate_test_underwriter_pubkey();
        let fork_version = [0x01, 0x00, 0x00, 0x00];
        let action = Action::Delegate;

        let result = generate_from_keystore(
            keys_path.to_str().unwrap(),
            keystore_secret,
            underwriter_pubkey,
            fork_version,
            action,
        );

        assert!(result.is_ok());
        let signed_messages = result.unwrap();
        assert_eq!(signed_messages.len(), 1);
    }

    #[test]
    fn test_generate_from_keystore_wrong_password() {
        let password = "correct_password";
        let wrong_password = "wrong_password";
        let (keys_path, _expected_pubkeys) = create_temp_keystore_dir(1, password);
        let keystore_secret = KeystoreSecret::from_unique_password(wrong_password.to_string());
        let underwriter_pubkey = generate_test_underwriter_pubkey();
        let fork_version = [0x01, 0x00, 0x00, 0x00];
        let action = Action::Delegate;

        let result = generate_from_keystore(
            keys_path.to_str().unwrap(),
            keystore_secret,
            underwriter_pubkey,
            fork_version,
            action,
        );

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("Eth2Keystore") || error.to_string().contains("decrypt")
        );
    }

    #[test]
    fn test_generate_from_keystore_nonexistent_path() {
        let keystore_secret = KeystoreSecret::from_unique_password("password".to_string());
        let underwriter_pubkey = generate_test_underwriter_pubkey();
        let fork_version = [0x01, 0x00, 0x00, 0x00];
        let action = Action::Delegate;

        let result = generate_from_keystore(
            "/nonexistent/path",
            keystore_secret,
            underwriter_pubkey,
            fork_version,
            action,
        );

        assert!(result.is_err());
    }
}
