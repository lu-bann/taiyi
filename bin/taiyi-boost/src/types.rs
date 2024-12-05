#![allow(unused)]
use std::{
    fmt::{self, Debug},
    ops::Deref,
    path::Path,
};

use alloy_consensus::{TxEip4844Variant, TxEnvelope};
use alloy_eips::{
    eip2718::{Decodable2718, Eip2718Result, Encodable2718},
    eip4895::{Withdrawal, Withdrawals},
};
use alloy_primitives::{Address, Bloom, Bytes, Log, LogData, B256, U256};
use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use alloy_rpc_types_engine::{
    ExecutionPayload as AlloyExecutionPayload, ExecutionPayloadV1, ExecutionPayloadV2,
    ExecutionPayloadV3, JwtError, JwtSecret,
};
use alloy_rpc_types_trace::geth::CallLogFrame;
use alloy_signer::k256::sha2::{Digest, Sha256};
use blst::min_pk::SecretKey as BlsSecretKey;
use cb_common::pbs::{
    Blob, BlobsBundle, DenebSpec, ExecutionPayload, ExecutionPayloadHeader, KzgCommitment,
    KzgCommitments, KzgProof, KzgProofs, Transactions, Withdrawal as cbWithdrawal,
};
use ethereum_consensus::{
    bellatrix::mainnet::Transaction as ConsensusTransaction,
    deneb::{
        mainnet::{Withdrawal as ConsensusWithdrawal, MAX_WITHDRAWALS_PER_PAYLOAD},
        minimal::MAX_TRANSACTIONS_PER_PAYLOAD,
        spec, ExecutionAddress, ExecutionPayload as DenebExecutionPayload,
    },
    networks::Network,
    ssz::prelude::{ssz_rs, ByteList, ByteVector, HashTreeRoot, List},
    types::mainnet::ExecutionPayload as ConsensusExecutionPayload,
};
use reqwest::Url;
use reth_primitives::{SealedBlock, Transaction, TransactionSigned};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use tree_hash_derive::TreeHash;

pub const BUILDER_CONSTRAINTS_PATH: &str = "/constraints";

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

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SignedConstraints {
    pub message: ConstraintsMessage,
    pub signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, Eq, PartialEq, Deserialize, Encode, Decode)]
pub struct ConstraintsMessage {
    pub pubkey: BlsPublicKey,
    pub slot: u64,
    pub top: bool,
    pub transactions: Vec<Bytes>,
}

impl ConstraintsMessage {
    /// Returns the digest of this message.
    pub fn digest(&self) -> Eip2718Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(self.pubkey);
        hasher.update(self.slot.to_le_bytes());
        hasher.update((self.top as u8).to_le_bytes());

        for bytes in &self.transactions {
            let tx = TxEnvelope::decode_2718(&mut bytes.as_ref())?;
            hasher.update(tx.tx_hash());
        }

        Ok(hasher.finalize().into())
    }
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

pub fn tx_envelope_to_signed(tx: TxEnvelope) -> TransactionSigned {
    let (transaction, signature, hash) = match tx {
        TxEnvelope::Legacy(tx) => {
            let (tx, sig, hash) = tx.into_parts();
            (Transaction::Legacy(tx), sig, hash)
        }
        TxEnvelope::Eip2930(tx) => {
            let (tx, sig, hash) = tx.into_parts();
            (Transaction::Eip2930(tx), sig, hash)
        }
        TxEnvelope::Eip1559(tx) => {
            let (tx, sig, hash) = tx.into_parts();
            (Transaction::Eip1559(tx), sig, hash)
        }
        TxEnvelope::Eip4844(tx) => {
            let (tx, sig, hash) = tx.into_parts();
            (Transaction::Eip4844(tx.into()), sig, hash)
        }
        TxEnvelope::Eip7702(tx) => {
            let (tx, sig, hash) = tx.into_parts();
            (Transaction::Eip7702(tx), sig, hash)
        }
        _ => panic!("Unsupported transaction type: {tx:?}"),
    };
    TransactionSigned { transaction, signature, hash }
}
pub fn to_blobs_bundle(transactions: &[TxEnvelope]) -> Option<BlobsBundle<DenebSpec>> {
    let blobs_bundle = transactions
        .iter()
        .filter_map(|tx| match tx {
            TxEnvelope::Eip4844(signed_tx) => match signed_tx.tx() {
                TxEip4844Variant::TxEip4844WithSidecar(sidecar_tx) => Some(sidecar_tx.sidecar()),
                _ => None,
            },
            _ => None,
        })
        .fold(
            BlobsBundle::<DenebSpec>::default(), // Initialize with an empty BlobsBundle
            |mut acc, sidecar| {
                for commitment in sidecar.commitments.iter() {
                    acc.commitments.push(KzgCommitment(
                        commitment.as_slice().try_into().expect("invalid commitment"),
                    ));
                }
                for proof in sidecar.proofs.iter() {
                    acc.proofs.push(KzgProof(proof.as_slice().try_into().expect("invalid proof")));
                }
                for blob in sidecar.blobs.iter() {
                    acc.blobs.push(Blob::<DenebSpec>::from(blob.as_slice().to_vec()));
                }
                acc
            },
        );
    if blobs_bundle.commitments.is_empty() {
        None
    } else {
        Some(blobs_bundle)
    }
}

pub fn to_cb_execution_payload(value: &SealedBlock) -> ExecutionPayload<DenebSpec> {
    let hash = value.hash();
    let header = &value.header;
    let transactions = &value.body.transactions;
    let withdrawals = &value.body.withdrawals;
    let transactions: Transactions<DenebSpec> = transactions
        .iter()
        .map(|t| VariableList::from(t.encoded_2718()))
        .collect::<Vec<_>>()
        .into();
    let withdrawals = VariableList::from(
        withdrawals
            .as_ref()
            .unwrap_or(&Withdrawals::default())
            .iter()
            .map(|w| cbWithdrawal {
                index: w.index,
                validator_index: w.validator_index,
                address: w.address,
                amount: w.amount,
            })
            .collect::<Vec<_>>(),
    );

    ExecutionPayload::<DenebSpec> {
        parent_hash: header.parent_hash,
        fee_recipient: header.beneficiary,
        state_root: header.state_root,
        receipts_root: header.receipts_root,
        logs_bloom: FixedVector::from(header.logs_bloom.as_slice().to_vec()),
        prev_randao: header.mix_hash,
        block_number: header.number,
        gas_limit: header.gas_limit,
        gas_used: header.gas_used,
        timestamp: header.timestamp,
        extra_data: VariableList::from(header.extra_data.as_ref().to_vec()),
        base_fee_per_gas: U256::from(header.base_fee_per_gas.unwrap_or_default()),
        block_hash: hash,
        transactions,
        withdrawals,
        blob_gas_used: value.blob_gas_used(),
        excess_blob_gas: value.excess_blob_gas.unwrap_or_default(),
    }
}

pub fn to_cb_execution_payload_header(value: &SealedBlock) -> ExecutionPayloadHeader<DenebSpec> {
    let header = &value.header;
    let transactions = &value.body.transactions;
    let withdrawals = &value.body.withdrawals;

    let transactions_bytes = transactions.iter().map(|t| t.encoded_2718()).collect::<Vec<_>>();

    let mut transactions_ssz: List<ConsensusTransaction, MAX_TRANSACTIONS_PER_PAYLOAD> =
        List::default();

    for tx in transactions_bytes {
        transactions_ssz.push(ConsensusTransaction::try_from(tx.as_ref()).expect("invalid tx"));
    }

    let transactions_root = B256::from_slice(
        transactions_ssz.hash_tree_root().expect("valid transactions root").as_slice(),
    );

    let mut withdrawals_ssz: List<ConsensusWithdrawal, MAX_WITHDRAWALS_PER_PAYLOAD> =
        List::default();

    if let Some(withdrawals) = withdrawals.as_ref() {
        for w in withdrawals.iter() {
            withdrawals_ssz.push(to_consensus_withdrawal(w));
        }
    }

    let withdrawals_root = B256::from_slice(
        withdrawals_ssz.hash_tree_root().expect("valid withdrawals root").as_slice(),
    );

    ExecutionPayloadHeader::<DenebSpec> {
        parent_hash: header.parent_hash,
        fee_recipient: header.beneficiary,
        state_root: header.state_root,
        receipts_root: header.receipts_root,
        logs_bloom: FixedVector::from(header.logs_bloom.as_slice().to_vec()),
        prev_randao: header.mix_hash,
        block_number: header.number,
        gas_limit: header.gas_limit,
        gas_used: header.gas_used,
        timestamp: header.timestamp,
        extra_data: VariableList::from(header.extra_data.as_ref().to_vec()),
        base_fee_per_gas: U256::from(header.base_fee_per_gas.unwrap_or_default()),
        block_hash: header.hash(),
        transactions_root,
        withdrawals_root,
        blob_gas_used: header.blob_gas_used.unwrap_or_default(),
        excess_blob_gas: header.excess_blob_gas.unwrap_or_default(),
    }
}
pub fn to_consensus_withdrawal(value: &Withdrawal) -> ethereum_consensus::capella::Withdrawal {
    ethereum_consensus::capella::Withdrawal {
        index: value.index as usize,
        validator_index: value.validator_index as usize,
        address: ExecutionAddress::try_from(value.address.as_ref()).expect("invalid address"),
        amount: value.amount,
    }
}
