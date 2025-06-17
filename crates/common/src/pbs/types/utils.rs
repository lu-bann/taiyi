use serde::{Deserialize, Serialize};

use crate::pbs::error::PbsError;
use futures::StreamExt;
use reqwest::Response;

pub mod quoted_variable_list_u64 {
    use serde::{ser::SerializeSeq, Deserializer, Serializer};
    use serde_utils::quoted_u64_vec::{QuotedIntVecVisitor, QuotedIntWrapper};
    use ssz_types::{typenum::Unsigned, VariableList};

    pub fn serialize<S, T>(value: &VariableList<u64, T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Unsigned,
    {
        let mut seq = serializer.serialize_seq(Some(value.len()))?;
        for &int in value.iter() {
            seq.serialize_element(&QuotedIntWrapper { int })?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<VariableList<u64, T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Unsigned,
    {
        deserializer.deserialize_any(QuotedIntVecVisitor).and_then(|vec| {
            VariableList::new(vec)
                .map_err(|e| serde::de::Error::custom(format!("invalid length: {:?}", e)))
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "version", content = "data")]
pub enum VersionedResponse<D, E> {
    #[serde(rename = "deneb")]
    Deneb(D),
    #[serde(rename = "electra")]
    Electra(E),
}

impl<D: Default, E> Default for VersionedResponse<D, E> {
    fn default() -> Self {
        Self::Deneb(D::default())
    }
}

impl<D, E> VersionedResponse<D, E> {
    pub fn version(&self) -> &str {
        match self {
            VersionedResponse::Deneb(_) => "deneb",
            VersionedResponse::Electra(_) => "electra",
        }
    }
}
pub async fn read_chunked_body_with_max(
    res: Response,
    max_size: usize,
) -> Result<Vec<u8>, PbsError> {
    let mut stream = res.bytes_stream();
    let mut response_bytes = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if response_bytes.len() + chunk.len() > max_size {
            // avoid spamming logs if the message is too large
            response_bytes.truncate(1024);
            return Err(PbsError::PayloadTooLarge {
                max: max_size,
                raw: String::from_utf8_lossy(&response_bytes).into_owned(),
            });
        }

        response_bytes.extend_from_slice(&chunk);
    }

    Ok(response_bytes)
}

const GAS_LIMIT_ADJUSTMENT_FACTOR: u64 = 1024;
const GAS_LIMIT_MINIMUM: u64 = 5_000;

/// Validates the gas limit against the parent gas limit, according to the
/// execution spec https://github.com/ethereum/execution-specs/blob/98d6ddaaa709a2b7d0cd642f4cfcdadc8c0808e1/src/ethereum/cancun/fork.py#L1118-L1154
pub fn check_gas_limit(gas_limit: u64, parent_gas_limit: u64) -> bool {
    let max_adjustment_delta = parent_gas_limit / GAS_LIMIT_ADJUSTMENT_FACTOR;
    if gas_limit >= parent_gas_limit + max_adjustment_delta {
        return false;
    }

    if gas_limit <= parent_gas_limit - max_adjustment_delta {
        return false;
    }

    if gas_limit < GAS_LIMIT_MINIMUM {
        return false;
    }

    true
}
