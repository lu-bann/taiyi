use std::{
    fmt::Debug,
    hash::{Hash, Hasher},
    ops::Deref,
};

use ahash::AHasher;
use alloy_consensus::{
    Block, Header, Sealed, Signed, TxEip4844Variant, TxEip4844WithSidecar, TxEnvelope,
};
use alloy_eips::{
    eip2718::{Decodable2718, Eip2718Error, Eip2718Result, Encodable2718},
    eip4895::{Withdrawal, Withdrawals},
};
use alloy_primitives::{keccak256, Address, Bytes, TxHash, B256, U256};
use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use alloy_rpc_types_engine::{ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3};
use alloy_signer::k256::sha2::{Digest, Sha256};
use axum::http::HeaderMap;
use cb_common::pbs::{
    Blob, BlobsBundle, DenebSpec, ElectraSpec, EthSpec, ExecutionPayload, ExecutionPayloadHeader,
    GetHeaderResponse, KzgCommitment, KzgProof, Transaction as cbTransaction, Transactions,
    Withdrawal as cbWithdrawal,
};
use ethereum_consensus::{
    bellatrix::mainnet::Transaction as ConsensusTransaction,
    deneb::{
        mainnet::{Withdrawal as ConsensusWithdrawal, MAX_WITHDRAWALS_PER_PAYLOAD},
        minimal::MAX_TRANSACTIONS_PER_PAYLOAD,
        ExecutionAddress,
    },
    networks::Network,
    ssz::prelude::{HashTreeRoot, List},
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use taiyi_beacon_client::{BlsSecretKeyWrapper, JwtSecretWrapper};
use tree_hash::TreeHash;

/// A hash tree root.
pub type HashTreeRootType = tree_hash::Hash256;
/// List of transaction hashes and the corresponding hash tree roots of the raw transactions.
pub type ConstraintsProofData = Vec<(TxHash, HashTreeRootType)>;

#[derive(Debug, Clone, Deserialize)]
pub struct ExtraConfig {
    pub engine_api: Url,
    pub execution_api: Url,
    pub beacon_api: Url,
    pub fee_recipient: Address,
    pub builder_private_key: BlsSecretKeyWrapper,
    pub engine_jwt: JwtSecretWrapper,
    pub network: Network,
    pub auth_token: Option<String>,
}

/// Minimal account state needed for commitment validation.
///
/// Each account state is 8 + 32 + 1 + 7 (padding) bytes = 48 bytes.
#[allow(unused)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AccountState {
    /// The nonce of the account. This is the number of transactions sent from this account
    pub transaction_count: u64,
    /// The balance of the account in wei
    pub balance: U256,
    /// Flag to indicate if the account is a smart contract or an EOA
    pub has_code: bool,
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

    pub fn hash(&self) -> u64 {
        let mut hasher = AHasher::default();

        self.pubkey.hash(&mut hasher);
        self.slot.hash(&mut hasher);
        self.top.hash(&mut hasher);

        for tx in &self.transactions {
            tx.hash(&mut hasher);
        }

        hasher.finish()
    }
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct ConstraintsData {
    pub transactions: Vec<TxEnvelope>,
    pub proof_data: ConstraintsProofData,
}

impl TryFrom<ConstraintsMessage> for ConstraintsData {
    type Error = Eip2718Error;

    fn try_from(message: ConstraintsMessage) -> Result<Self, Self::Error> {
        let transactions: Vec<TxEnvelope> = message
            .transactions
            .iter()
            .map(|bytes| TxEnvelope::decode_2718(&mut bytes.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;

        let proof_data = message
            .transactions
            .iter()
            .map(calculate_tx_proof_data)
            .collect::<Result<Vec<_>, Eip2718Error>>()?;

        Ok(Self { transactions, proof_data })
    }
}

/// Takes a raw EIP-2718 RLP-encoded transaction and calculates its proof data, consisting of its
/// hash and the hash tree root of the transaction. For type 3 transactions, the hash tree root of
/// the inner transaction is computed without blob sidecar.
fn calculate_tx_proof_data(raw_tx: &Bytes) -> Result<(TxHash, HashTreeRootType), Eip2718Error> {
    let Some(is_type_3) = raw_tx.first().map(|type_id| type_id == &0x03) else {
        return Err(Eip2718Error::RlpError(alloy_rlp::Error::Custom("empty RLP bytes")));
    };

    // For blob transactions (type 3), we need to make sure to strip out the blob sidecar when
    // calculating both the transaction hash and the hash tree root
    if !is_type_3 {
        let tx_hash = keccak256(raw_tx);
        return Ok((tx_hash, hash_tree_root_raw_tx(raw_tx.to_vec())));
    }

    let envelope = TxEnvelope::decode_2718(&mut raw_tx.as_ref())?;
    let TxEnvelope::Eip4844(signed_tx) = envelope else {
        unreachable!("we have already checked it is not a type 3 transaction")
    };
    let (tx, signature, tx_hash) = signed_tx.into_parts();
    match tx {
        TxEip4844Variant::TxEip4844(_) => {
            // We have the type 3 variant without sidecar, we can safely compute the hash tree root
            // of the transaction from the raw RLP bytes.
            Ok((tx_hash, hash_tree_root_raw_tx(raw_tx.to_vec())))
        }
        TxEip4844Variant::TxEip4844WithSidecar(TxEip4844WithSidecar { tx, .. }) => {
            // We strip out the sidecar and compute the hash tree root the transaction
            let signed = Signed::new_unchecked(tx, signature, tx_hash);
            let new_envelope = TxEnvelope::from(signed);
            let mut buf = Vec::new();
            new_envelope.encode_2718(&mut buf);

            Ok((tx_hash, hash_tree_root_raw_tx(buf)))
        }
    }
}

fn hash_tree_root_raw_tx(raw_tx: Vec<u8>) -> HashTreeRootType {
    let tx = cbTransaction::<<DenebSpec as EthSpec>::MaxBytesPerTransaction>::from(raw_tx);
    TreeHash::tree_hash_root(&tx)
}

pub type GetHeaderWithProofsResponse = SignedExecutionPayloadHeaderWithProofs;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignedExecutionPayloadHeaderWithProofs {
    #[serde(flatten)]
    pub header: GetHeaderResponse,
    #[serde(default)]
    pub proofs: InclusionProofs,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct InclusionProofs {
    /// The transaction hashes these inclusion proofs are for. The hash tree roots of
    /// these transactions are the leaves of the transactions tree.
    pub transaction_hashes: Vec<TxHash>,
    /// The generalized indexes of the nodes in the transactions tree.
    pub generalized_indexes: Vec<usize>,
    /// The proof hashes for the transactions tree.
    pub merkle_hashes: Vec<B256>,
}

impl InclusionProofs {
    /// Returns the total number of leaves in the tree.
    pub fn total_leaves(&self) -> usize {
        self.transaction_hashes.len()
    }
}

impl Deref for SignedExecutionPayloadHeaderWithProofs {
    type Target = GetHeaderResponse;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

#[derive(Debug)]
pub struct RequestConfig {
    pub url: Url,
    pub timeout_ms: u64,
    pub headers: HeaderMap,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionPayloadV4 {
    /// Inner V2 payload
    #[serde(flatten)]
    pub payload_inner: ExecutionPayloadV3,

    pub execution_requests: Vec<Bytes>,
}

pub(crate) fn to_alloy_execution_payload(
    block: &Block<TxEnvelope, Sealed<Header>>,
) -> ExecutionPayloadV4 {
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

    ExecutionPayloadV4 {
        payload_inner: ExecutionPayloadV3 {
            blob_gas_used: block.header.blob_gas_used.unwrap_or_default(),
            excess_blob_gas: block.header.excess_blob_gas.unwrap_or_default(),
            payload_inner: ExecutionPayloadV2 {
                payload_inner: ExecutionPayloadV1 {
                    base_fee_per_gas: U256::from(block.header.base_fee_per_gas.unwrap_or_default()),
                    block_hash: block.header.hash(),
                    block_number: block.header.number,
                    extra_data: block.header.extra_data.clone(),
                    transactions: block
                        .body
                        .transactions()
                        .map(|tx| tx.encoded_2718())
                        .map(Into::into)
                        .collect(),
                    fee_recipient: block.header.beneficiary,
                    gas_limit: block.header.gas_limit,
                    gas_used: block.header.gas_used,
                    logs_bloom: block.header.logs_bloom,
                    parent_hash: block.header.parent_hash,
                    prev_randao: block.header.mix_hash,
                    receipts_root: block.header.receipts_root,
                    state_root: block.header.state_root,
                    timestamp: block.header.timestamp,
                },
                withdrawals: alloy_withdrawals,
            },
        },
        execution_requests: vec![],
    }
}

// NOTE: This returns an empty BlobsBundle if there are no blob transactions
pub fn to_blobs_bundle(transactions: &[TxEnvelope]) -> BlobsBundle<ElectraSpec> {
    transactions
        .iter()
        .filter_map(|tx| match tx {
            TxEnvelope::Eip4844(signed_tx) => match signed_tx.tx() {
                TxEip4844Variant::TxEip4844WithSidecar(sidecar_tx) => Some(sidecar_tx.sidecar()),
                _ => None,
            },
            _ => None,
        })
        .fold(
            BlobsBundle::<ElectraSpec>::default(), // Initialize with an empty BlobsBundle
            |mut acc, sidecar| {
                for commitment in sidecar.commitments.iter() {
                    acc.commitments
                        .push(KzgCommitment(
                            commitment.as_slice().try_into().expect("invalid commitment"),
                        ))
                        .ok();
                }
                for proof in sidecar.proofs.iter() {
                    acc.proofs
                        .push(KzgProof(proof.as_slice().try_into().expect("invalid proof")))
                        .ok();
                }
                for blob in sidecar.blobs.iter() {
                    acc.blobs.push(Blob::<ElectraSpec>::from(blob.as_slice().to_vec())).ok();
                }
                acc
            },
        )
}

pub fn to_cb_execution_payload(
    value: &Block<TxEnvelope, Sealed<Header>>,
) -> ExecutionPayload<ElectraSpec> {
    let hash = value.header.hash();
    let header = &value.header;
    let transactions = &value.body.transactions;
    let withdrawals = &value.body.withdrawals;
    let transactions: Transactions<ElectraSpec> = transactions
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

    ExecutionPayload::<ElectraSpec> {
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
        blob_gas_used: value.header.blob_gas_used.unwrap_or_default(),
        excess_blob_gas: value.header.excess_blob_gas.unwrap_or_default(),
    }
}

pub fn to_cb_execution_payload_header(
    value: &Block<TxEnvelope, Sealed<Header>>,
) -> ExecutionPayloadHeader<ElectraSpec> {
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

    ExecutionPayloadHeader::<ElectraSpec> {
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
