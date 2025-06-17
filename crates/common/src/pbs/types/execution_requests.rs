use alloy::primitives::{Address, B256};
use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use serde::{Deserialize, Serialize};
use ssz_types::VariableList;

use super::spec::{DenebSpec, ElectraSpec, EthSpec};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ExecutionRequests<T: EthSpec> {
    pub deposits: VariableList<DepositRequest, T::MaxDepositRequestsPerPayload>,
    pub withdrawals: VariableList<WithdrawalRequest, T::MaxWithdrawalRequestsPerPayload>,
    pub consolidations: VariableList<ConsolidationRequest, T::MaxConsolidationRequestsPerPayload>,
}

impl ssz::Decode for ExecutionRequests<DenebSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Decode for ExecutionRequests<ElectraSpec> {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for ExecutionRequests<DenebSpec> {
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

impl ssz::Encode for ExecutionRequests<ElectraSpec> {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositRequest {
    pub pubkey: BlsPublicKey,
    pub withdrawal_credentials: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    pub signature: BlsSignature,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
}

impl ssz::Decode for DepositRequest {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for DepositRequest {
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

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    pub source_address: Address,
    pub validator_pubkey: BlsPublicKey,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}

impl ssz::Decode for WithdrawalRequest {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for WithdrawalRequest {
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

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ConsolidationRequest {
    pub source_address: Address,
    pub source_pubkey: BlsPublicKey,
    pub target_pubkey: BlsPublicKey,
}

impl ssz::Decode for ConsolidationRequest {
    fn is_ssz_fixed_len() -> bool {
        false
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(serde_json::from_slice(bytes).unwrap())
    }
}

impl ssz::Encode for ConsolidationRequest {
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
