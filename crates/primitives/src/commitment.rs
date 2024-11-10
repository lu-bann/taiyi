use std::str::FromStr;

use alloy_primitives::Signature;
use serde::{de, Deserialize, Deserializer, Serialize};

use crate::inclusion_request::InclusionRequest;

/// A signed inclusion commitment with a generic signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionCommitment {
    #[serde(flatten)]
    pub request: InclusionRequest,
    #[serde(deserialize_with = "deserialize_sig", serialize_with = "serialize_sig")]
    pub signature: Signature,
}

fn deserialize_sig<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let s = String::deserialize(deserializer)?;
    T::from_str(s.trim_start_matches("0x")).map_err(de::Error::custom)
}

fn serialize_sig<S: serde::Serializer>(sig: &Signature, serializer: S) -> Result<S::Ok, S::Error> {
    let parity = sig.v();
    // As bytes encodes the parity as 27/28, need to change that.
    let mut bytes = sig.as_bytes();
    bytes[bytes.len() - 1] = if parity.y_parity() { 1 } else { 0 };
    serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
}
