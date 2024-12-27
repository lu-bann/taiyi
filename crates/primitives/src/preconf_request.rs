use alloy_consensus::TxEnvelope;
use alloy_primitives::{keccak256, Address, B256, U256};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PreconfRequest {
    /// blockspace allocated
    pub allocation: BlockspaceAllocation,
    /// Preconf transaction
    pub transaction: Option<TxEnvelope>,
    /// The signer of the transaction
    #[serde(skip)]
    pub signer: Option<Address>,
}

impl PreconfRequest {
    /// Returns the transaction signer.
    pub fn signer(&self) -> Option<Address> {
        self.signer
    }

    /// Sets the signer.
    pub fn set_signer(&mut self, signer: Address) {
        self.signer = Some(signer);
    }

    /// Target slot
    pub fn target_slot(&self) -> u64 {
        self.allocation.target_slot
    }
}

/// Amount of blockspace to be allocated
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct BlockspaceAllocation {
    /// The slot to reserve blockspace for
    pub target_slot: u64,
    /// The gas limit for the block
    /// This is the maximum amount of gas that can be used in the block
    pub gas_limit: u64,
    /// Deposit to be locked from the sender's escrow balance
    /// This must be equal to gas_limit * fee_qouted_to_user
    pub deposit: U256,
    /// Number of blobs to reserve
    pub num_blobs: usize,
}

impl BlockspaceAllocation {
    pub fn new(target_slot: u64, gas_limit: u64, deposit: U256, num_blobs: usize) -> Self {
        Self { target_slot, gas_limit, deposit, num_blobs }
    }

    pub fn digest(&self) -> B256 {
        let mut digest = Vec::new();
        digest.extend_from_slice(&self.target_slot.to_le_bytes());
        digest.extend_from_slice(&self.gas_limit.to_le_bytes());
        digest.extend_from_slice(&self.deposit.to_le_bytes::<32>());
        digest.extend_from_slice(&(self.num_blobs as u64).to_le_bytes());
        keccak256(&digest)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SubmitTransactionRequest {
    pub request_id: Uuid,
    pub transaction: TxEnvelope,
}

impl SubmitTransactionRequest {
    pub fn new(request_id: Uuid, transaction: TxEnvelope) -> Self {
        Self { request_id, transaction }
    }

    pub fn digest(&self) -> B256 {
        let mut digest = Vec::new();
        digest.extend_from_slice(&self.request_id.to_bytes_le());
        digest.extend_from_slice(self.transaction.tx_hash().as_slice());
        keccak256(&digest)
    }
}
