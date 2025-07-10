use alloy::consensus::TxEnvelope;
use alloy::primitives::{Address, Bytes, TxHash, B256, U256};
use serde::{Deserialize, Serialize};
use taiyi_primitives::{PreconfRequestTypeA, PreconfRequestTypeB};

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
