use core::fmt;
use std::ops::Deref;

use blst::min_pk::SecretKey as BlsSecretKey;
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct BlsSecretKeyWrapper(pub BlsSecretKey);

impl<'de> Deserialize<'de> for BlsSecretKeyWrapper {
    fn deserialize<D>(deserializer: D) -> Result<BlsSecretKeyWrapper, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let sk = String::deserialize(deserializer)?;
        Ok(BlsSecretKeyWrapper::from(sk.as_str()))
    }
}

impl From<&str> for BlsSecretKeyWrapper {
    fn from(sk: &str) -> Self {
        let hex_sk = sk.strip_prefix("0x").unwrap_or(sk);
        let sk =
            BlsSecretKey::from_bytes(&hex::decode(hex_sk).expect("valid hex")).expect("valid sk");
        BlsSecretKeyWrapper(sk)
    }
}

impl Deref for BlsSecretKeyWrapper {
    type Target = BlsSecretKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for BlsSecretKeyWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", const_hex::encode_prefixed(self.0.to_bytes()))
    }
}
