//! Provides a JSON keystore for a BLS keypair, as specified by
//! [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335).

mod derived_key;
mod keystore;

pub mod json_keystore;

pub use bls::ZeroizeHash;
pub use keystore::{
    decrypt, default_kdf, encrypt, keypair_from_secret, Error, Keystore, KeystoreBuilder, DKLEN,
    HASH_SIZE, IV_SIZE, SALT_SIZE,
};
pub use uuid::Uuid;

use zeroize::Zeroize;

/// Provides wrapper around `Vec<u8>` that implements `Zeroize`.
#[derive(Zeroize, Clone, PartialEq)]
#[zeroize(drop)]
pub struct PlainText(Vec<u8>);

impl PlainText {
    /// Instantiate self with `len` zeros.
    pub fn zero(len: usize) -> Self {
        Self(vec![0; len])
    }

    /// The byte-length of `self`
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Checks whether `self` is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns a reference to the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns a mutable reference to the underlying bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl From<Vec<u8>> for PlainText {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}

impl AsRef<[u8]> for PlainText {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
