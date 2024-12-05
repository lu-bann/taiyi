#![allow(unused)]
use std::{
    fmt::{self, Debug},
    ops::Deref,
    path::Path,
};

use alloy_eips::eip4895::Withdrawal;
use alloy_primitives::{Address, Log, LogData, B256, U256};
use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use alloy_rpc_types_engine::{
    ExecutionPayload as AlloyExecutionPayload, ExecutionPayloadV1, ExecutionPayloadV2,
    ExecutionPayloadV3, JwtError, JwtSecret,
};
use alloy_rpc_types_trace::geth::CallLogFrame;
use blst::min_pk::SecretKey as BlsSecretKey;
use ethereum_consensus::networks::Network;
use reqwest::Url;
use reth_primitives::SealedBlock;
use serde::{Deserialize, Serialize};
use tree_hash_derive::TreeHash;

pub const ELECT_PRECONFER_PATH: &str = "/elect_preconfer";

#[derive(Debug, Clone, Deserialize)]
pub struct ExtraConfig {
    pub engine_api: Url,
    pub execution_api: Url,
    pub beacon_api: Url,
    pub fee_recipient: Address,
    pub builder_private_key: BlsSecretKeyWrapper,
    pub engine_jwt: JwtSecretWrapper,
    pub network: Network,
}

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

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, TreeHash)]
pub struct ElectPreconferRequest {
    pub preconfer_pubkey: BlsPublicKey,
    pub slot_number: u64,
    pub chain_id: u64,
    pub gas_limit: u64,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize)]
pub struct SignedRequest<T>
where
    T: Debug + Default + Clone + Eq + PartialEq + Serialize,
{
    pub message: T,
    pub signature: BlsSignature,
}

pub fn to_alloy_withdrawal(value: ethereum_consensus::deneb::Withdrawal) -> Withdrawal {
    Withdrawal {
        index: value.index as u64,
        validator_index: value.validator_index as u64,
        address: Address::from_slice(value.address.as_ref()),
        amount: value.amount,
    }
}

pub(crate) fn to_alloy_execution_payload(
    block: &SealedBlock,
    block_hash: B256,
) -> AlloyExecutionPayload {
    let alloy_withdrawals = block
        .body
        .withdrawals
        .as_ref()
        .map(|withdrawals| {
            withdrawals
                .iter()
                .map(|w| Withdrawal {
                    index: w.index,
                    validator_index: w.validator_index,
                    address: w.address,
                    amount: w.amount,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    AlloyExecutionPayload::V3(ExecutionPayloadV3 {
        blob_gas_used: block.blob_gas_used(),
        excess_blob_gas: block.excess_blob_gas.unwrap_or_default(),
        payload_inner: ExecutionPayloadV2 {
            payload_inner: ExecutionPayloadV1 {
                base_fee_per_gas: U256::from(block.base_fee_per_gas.unwrap_or_default()),
                block_hash,
                block_number: block.number,
                extra_data: block.extra_data.clone(),
                transactions: block.raw_transactions(),
                fee_recipient: block.header.beneficiary,
                gas_limit: block.gas_limit,
                gas_used: block.gas_used,
                logs_bloom: block.logs_bloom,
                parent_hash: block.parent_hash,
                prev_randao: block.mix_hash,
                receipts_root: block.receipts_root,
                state_root: block.state_root,
                timestamp: block.timestamp,
            },
            withdrawals: alloy_withdrawals,
        },
    })
}

pub fn call_log_frame_to_log(log_frame: CallLogFrame) -> Option<Log> {
    let address = log_frame.address?;
    let topics = log_frame.topics?;
    let data = log_frame.data?;

    LogData::new(topics, data).map(|data| Log { address, data })
}

pub fn call_log_frams_to_logs(log_frames: Vec<CallLogFrame>) -> Vec<Log> {
    log_frames.into_iter().filter_map(call_log_frame_to_log).collect()
}
