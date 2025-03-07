use alloy_consensus::TxEnvelope;
use alloy_primitives::{keccak256, Address, Bytes, PrimitiveSignature, TxHash, B256, U256};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct PreconfRequestTypeA {
    pub tip_transaction: TxEnvelope,
    pub transactions: Vec<TxEnvelope>,
    pub target_slot: u64,
    pub sequence_number: u64,
    pub preconf_sig: PrimitiveSignature, /* signature by gateway (over tip transaction, preconf_txs, target_slot, and sequence_number) */
}

impl PreconfRequestTypeA {
    pub fn digest(&self) -> B256 {
        let mut digest = Vec::new();
        digest.extend_from_slice(self.tip_transaction.tx_hash().as_slice());
        for tx in &self.transactions {
            digest.extend_from_slice(tx.tx_hash().as_slice());
        }
        digest.extend_from_slice(&self.target_slot.to_be_bytes());
        digest.extend_from_slice(&self.sequence_number.to_be_bytes());
        keccak256(&digest)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BlockspaceAllocation {
    pub target_slot: u64,
    pub gas_limit: u64,
    pub deposit: U256,
    pub tip: U256,
    pub blob_count: usize,
}

impl BlockspaceAllocation {
    pub fn blockspace_digest(&self) -> Vec<u8> {
        let mut digest = Vec::new();
        digest.extend_from_slice(&self.target_slot.to_le_bytes());
        digest.extend_from_slice(&self.gas_limit.to_le_bytes());
        digest.extend_from_slice(&self.deposit.to_le_bytes::<32>());
        digest.extend_from_slice(&self.tip.to_le_bytes::<32>());
        digest.extend_from_slice(&(self.blob_count as u64).to_le_bytes());
        digest
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PreconfRequestTypeB {
    pub allocation: BlockspaceAllocation,
    pub alloc_sig: PrimitiveSignature, // signature by user (over allocation)
    pub transaction: TxEnvelope,       // signed by user, TODO: change to array
    pub preconf_sig: PrimitiveSignature, // signature by gateway (over allocation and transaction)
}

impl PreconfRequestTypeB {
    pub fn digest(&self) -> B256 {
        let mut digest = Vec::new();
        digest.extend_from_slice(&self.allocation.blockspace_digest());
        digest.extend_from_slice(self.transaction.tx_hash().as_slice());
        keccak256(&digest)
    }
}

#[derive(Serialize, Deserialize)]
pub struct TxMerkleProof {
    pub key: Vec<u8>,
    pub proof: Vec<Vec<u8>>,
    pub root: B256,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AccountMerkleProof {
    pub address: Address,
    pub nonce: u64,
    pub balance: U256,
    pub storage_hash: B256,
    pub code_hash: B256,
    pub account_proof: Vec<Bytes>,
    pub state_root: B256,
}

#[derive(Serialize, Deserialize)]
pub struct PreconfTypeA {
    pub preconf: PreconfRequestTypeA,
    pub anchor_tx: TxEnvelope,
    pub tx_merkle_proof: Vec<TxMerkleProof>, /* Inclusion proofs of the user transaction and anchor tx in the block */
    pub account_merkle_proof: Vec<AccountMerkleProof>, /* Merkle proofs of the account states (user's) */
}

#[derive(Serialize, Deserialize)]
pub struct PreconfTypeB {
    pub preconf: PreconfRequestTypeB,
    pub sponsorship_tx: TxEnvelope,
    pub tx_merkle_proof: Vec<TxMerkleProof>, /* Inclusion proofs of the user transaction and sponsorship tx in the block */
    pub account_merkle_proof: AccountMerkleProof, // Merkle proof of the account state (user's)
}

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("Leaves and indices length mismatch")]
    LengthMismatch,
    #[error("Mismatch in provided leaves and leaves to prove")]
    LeavesMismatch,
    #[error("Hash not found in constraints cache: {0:?}")]
    MissingHash(TxHash),
    #[error("Proof verification failed")]
    VerificationFailed,
}
