// codes are basicall copied from https://github.com/chainbound/bolt/blob/89253d92b079adf0abf6c9279eeed1d5dc7a3aed/bolt-cli/src/common/keystore.rs
use std::{
    collections::HashMap,
    ffi::OsString,
    fs::{self, DirEntry},
    io,
    path::{Path, PathBuf},
};

use clap::Parser;
use eyre::{bail, Context, ContextCompat, Result};
use zeroize::Zeroize;

/// Default password used for keystores in the test vectors.
///
/// Reference: https://eips.ethereum.org/EIPS/eip-2335#test-cases
pub const DEFAULT_KEYSTORE_PASSWORD: &str = r#"𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"#;

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("failed to read keystore directory: {0}")]
    ReadFromDirectory(#[from] std::io::Error),
    #[error("Failed to read or decrypt keystore: {0:?}")]
    Eth2Keystore(lighthouse_eth2_keystore::Error),
    #[error("Missing password for keypair")]
    MissingPassword,
}

/// EIP-2335 keystore secret kind.
pub enum KeystoreSecret {
    /// When using a unique password for all validators in the keystore
    /// (e.g. for Prysm keystore)
    Unique(String),
    /// When using a directory to hold individual passwords for each validator
    /// according to the format: secrets/0x{validator_pubkey} = {password}
    Directory(HashMap<String, String>),
}

impl KeystoreSecret {
    /// Create a new [`KeystoreSecret`] from the provided [`LocalKeystoreOpts`].
    pub fn from_keystore_options(opts: &LocalKeystoreOpts) -> Result<Self> {
        if let Some(password_path) = &opts.password_path {
            Ok(KeystoreSecret::from_directory(password_path)?)
        } else if let Some(password) = &opts.password {
            Ok(KeystoreSecret::from_unique_password(password.clone()))
        } else {
            // This case is prevented upstream by clap's validation.
            bail!("Either `password_path` or `password` must be provided")
        }
    }

    /// Load the keystore passwords from a directory containing individual password files.
    pub fn from_directory(root_dir: &str) -> Result<Self> {
        let mut secrets = HashMap::new();
        for entry in fs::read_dir(root_dir)? {
            let entry = entry.wrap_err("Failed to read secrets directory entry")?;
            let path = entry.path();

            let filename = path.file_name().wrap_err("Secret file name")?.to_string_lossy();
            let secret = fs::read_to_string(&path).wrap_err("Failed to read secret file")?;
            secrets.insert(filename.trim_start_matches("0x").to_string(), secret);
        }
        Ok(KeystoreSecret::Directory(secrets))
    }

    /// Set a unique password for all validators in the keystore.
    pub fn from_unique_password(password: String) -> Self {
        KeystoreSecret::Unique(password)
    }

    /// Get the password for the given validator public key.
    pub fn get(&self, validator_pubkey: &str) -> Option<&str> {
        match self {
            KeystoreSecret::Unique(password) => Some(password.as_str()),
            KeystoreSecret::Directory(secrets) => secrets.get(validator_pubkey).map(|s| s.as_str()),
        }
    }
}

/// Manual drop implementation to clear the password from memory
/// when the KeystoreSecret is dropped.
impl Drop for KeystoreSecret {
    fn drop(&mut self) {
        match self {
            KeystoreSecret::Unique(password) => {
                password.zeroize();
            }
            KeystoreSecret::Directory(secrets) => {
                for secret in secrets.values_mut() {
                    secret.zeroize();
                }
            }
        }
    }
}

/// Returns the paths of all the keystore files provided in `keys_path`.
///
/// We're expecting a directory structure like:
/// ${keys_path}/
/// -- 0x1234.../validator.json
/// -- 0x5678.../validator.json
/// -- ...
pub fn keystore_paths(keys_path: &str) -> Result<Vec<PathBuf>> {
    let keys_path = Path::new(keys_path).to_path_buf();
    let json_extension = OsString::from("json");

    let mut keystores_paths = vec![];
    // Iter over the `keys` directory
    for entry in read_dir(keys_path)? {
        let path = read_path(entry)?;
        if path.is_dir() {
            for entry in read_dir(path)? {
                let path = read_path(entry)?;
                if path.is_file() && path.extension() == Some(&json_extension) {
                    keystores_paths.push(path);
                }
            }
        }
    }

    Ok(keystores_paths)
}

fn read_path(entry: io::Result<DirEntry>) -> Result<PathBuf> {
    Ok(entry.map_err(KeystoreError::ReadFromDirectory)?.path())
}

fn read_dir(path: PathBuf) -> Result<fs::ReadDir> {
    fs::read_dir(path).wrap_err("Failed to read directory")
}

/// Options for reading a keystore folder.
#[derive(Debug, Clone, Parser)]
pub struct LocalKeystoreOpts {
    /// The path to the keystore file.
    #[clap(long, env = "KEYSTORE_PATH", default_value = "validators")]
    pub path: String,

    /// The password for the keystore files in the path.
    /// Assumes all keystore files have the same password.
    #[clap(
        long,
        env = "KEYSTORE_PASSWORD",
        hide_env_values = true,
        conflicts_with = "password_path"
    )]
    pub password: Option<String>,

    #[clap(long, env = "KEYSTORE_PASSWORD_PATH", conflicts_with = "password")]
    pub password_path: Option<String>,
}
