use core::fmt;
use std::{ops::Deref, path::Path};

use alloy_rpc_types_engine::{JwtError, JwtSecret};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct JwtSecretWrapper(pub JwtSecret);

impl<'de> Deserialize<'de> for JwtSecretWrapper {
    fn deserialize<D>(deserializer: D) -> Result<JwtSecretWrapper, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        JwtSecretWrapper::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<&str> for JwtSecretWrapper {
    type Error = JwtError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let jwt = if Path::new(&s).exists() {
            JwtSecret::from_file(Path::new(&s))
        } else {
            JwtSecret::from_hex(s)
        }?;
        Ok(JwtSecretWrapper(jwt))
    }
}

impl Deref for JwtSecretWrapper {
    type Target = JwtSecret;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for JwtSecretWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
