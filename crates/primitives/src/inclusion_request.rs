use std::borrow::Cow;

use alloy_primitives::{Address, Bytes, Signature};
use alloy_rlp::{Decodable, Encodable};
use reth_primitives::PooledTransactionsElement;
use serde::{de, ser::SerializeSeq, Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionRequest {
    /// The consensus slot number at which the transaction should be included.
    pub slot: u64,
    /// The transaction to be included.
    #[serde(deserialize_with = "deserialize_txs", serialize_with = "serialize_txs")]
    pub txs: Vec<FullTransaction>,
    /// The signature over the "slot" and "tx" fields by the user.
    /// A valid signature is the only proof that the user actually requested
    /// this specific commitment to be included at the given slot.
    #[serde(skip)]
    pub signature: Option<Signature>,
    #[serde(skip)]
    pub signer: Option<Address>,
}

impl InclusionRequest {
    /// Returns the transaction signer.
    pub fn signer(&self) -> Option<Address> {
        self.signer
    }

    /// Sets the signature.
    pub fn set_signature(&mut self, signature: Signature) {
        self.signature = Some(signature);
    }

    /// Sets the signer.
    pub fn set_signer(&mut self, signer: Address) {
        self.signer = Some(signer);
    }
}

/// Serialize a list of transactions into a sequence of hex-encoded strings.
pub fn serialize_txs<S: serde::Serializer>(
    txs: &[FullTransaction],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut seq = serializer.serialize_seq(Some(txs.len()))?;
    for tx in txs {
        let mut buf = Vec::new();
        tx.tx.encode(&mut buf);
        let encoded: Bytes = buf.into();
        seq.serialize_element(&format!("0x{}", hex::encode(encoded)))?;
    }
    seq.end()
}

/// Deserialize a list of transactions from a sequence of hex-encoded strings.
pub fn deserialize_txs<'de, D>(deserializer: D) -> Result<Vec<FullTransaction>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_strings = <Vec<Cow<'_, str>> as de::Deserialize>::deserialize(deserializer)?;
    let mut txs = Vec::with_capacity(hex_strings.len());

    for s in hex_strings {
        let data = hex::decode(s.trim_start_matches("0x")).map_err(de::Error::custom)?;
        let tx = PooledTransactionsElement::decode(&mut data.as_slice())
            .map_err(de::Error::custom)
            .map(|tx| FullTransaction { tx, sender: None })?;
        txs.push(tx);
    }

    Ok(txs)
}

/// A wrapper type for a full, complete transaction (i.e. with blob sidecars attached).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullTransaction {
    pub tx: PooledTransactionsElement,
    pub sender: Option<Address>,
}
