use serde::{Deserialize, Serialize};
use ssz_types::{FixedVector, VariableList};

use super::{
    kzg::{KzgCommitments, KzgProofs},
    spec::{DenebSpec, ElectraSpec, EthSpec},
};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec")]
pub struct BlobsBundle<T: EthSpec> {
    pub commitments: KzgCommitments<T>,
    pub proofs: KzgProofs<T>,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_fixed_vec")]
    pub blobs: VariableList<Blob<T>, <T as EthSpec>::MaxBlobCommitmentsPerBlock>,
}

impl ssz::Decode for BlobsBundle<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Decode for BlobsBundle<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for BlobsBundle<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl ssz::Encode for BlobsBundle<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut serde_json::to_vec(self).unwrap())
    }
    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

pub type Blob<T> = FixedVector<u8, <T as EthSpec>::BytesPerBlob>;
