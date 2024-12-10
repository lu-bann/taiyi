use alloy_consensus::TxEnvelope;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PreconfRequest {
    pub allocation: BlockspaceAllocation,
    pub transaction: Option<TxEnvelope>,
    pub target_slot: u64,
}

/// Amount of blockspace to be allocated
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct BlockspaceAllocation {
    /// Amount of gas to be allocated
    pub gas_limit: u64,
    /// Number of blobs to be allocated
    pub blobs: usize,
}

impl BlockspaceAllocation {
    pub fn new(gas_limit: u64, blobs: usize) -> Self {
        Self { gas_limit, blobs }
    }
}
