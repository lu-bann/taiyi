use alloy::primitives::{Address, B256};
use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use serde::{Deserialize, Serialize};
use ssz_types::VariableList;
use ssz_derive::{Decode, Encode};

use super::spec::{DenebSpec, ElectraSpec, EthSpec};

#[derive(Debug, Default, Clone, Serialize, Deserialize, Decode, Encode)]
pub struct ExecutionRequests<T: EthSpec> {
    pub deposits: VariableList<DepositRequest, T::MaxDepositRequestsPerPayload>,
    pub withdrawals: VariableList<WithdrawalRequest, T::MaxWithdrawalRequestsPerPayload>,
    pub consolidations: VariableList<ConsolidationRequest, T::MaxConsolidationRequestsPerPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Decode, Encode)]
pub struct DepositRequest {
    pub pubkey: BlsPublicKey,
    pub withdrawal_credentials: B256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
    pub signature: BlsSignature,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Decode, Encode)]
pub struct WithdrawalRequest {
    pub source_address: Address,
    pub validator_pubkey: BlsPublicKey,
    #[serde(with = "serde_utils::quoted_u64")]
    pub amount: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Decode, Encode)]
pub struct ConsolidationRequest {
    pub source_address: Address,
    pub source_pubkey: BlsPublicKey,
    pub target_pubkey: BlsPublicKey,
}
