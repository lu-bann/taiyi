use std::borrow::Cow;

use alloy_primitives::{Address, Signature};
// use alloy_rlp::{Decodable, Encodable};
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
        let encoded = tx.tx.envelope_encoded();
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
        let tx = PooledTransactionsElement::decode_enveloped(&mut data.as_slice())
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

#[cfg(test)]
mod tests {
    use crate::inclusion_request::InclusionRequest;

    #[test]
    fn test_deserialize_inclusion_request() {
        let json_req = r#"{
            "slot": 10,
            "txs": ["0x02f86c870c72dd9d5e883e4d0183408f2382520894d2e2adf7177b7a8afddbc12d1634cf23ea1a71020180c001a08556dcfea479b34675db3fe08e29486fe719c2b22f6b0c1741ecbbdce4575cc6a01cd48009ccafd6b9f1290bbe2ceea268f94101d1d322c787018423ebcbc87ab4"]
        }"#;

        let req: InclusionRequest = serde_json::from_str(json_req).unwrap();
        assert_eq!(req.slot, 10);

        let deser = serde_json::to_string(&req).unwrap();

        assert_eq!(
            deser.parse::<serde_json::Value>().unwrap(),
            json_req.parse::<serde_json::Value>().unwrap()
        );
    }
}
