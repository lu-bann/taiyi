use alloy_primitives::U256;
use reth_primitives::PooledTransactionsElement;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PreconfRequest {
    pub blockspace_allocation: BlockspaceAllocation,
    pub transaction: Option<PooledTransactionsElement>,
    pub target_slot: u64,
}

/// Amount of blockspace to be allocated
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct BlockspaceAllocation {
    /// Amount of gas to be allocated
    pub gas_limit: U256,
    /// Number of blobs to be allocated
    pub blobs: u8,
}

impl BlockspaceAllocation {
    pub fn new(gas_limit: U256, blobs: u8) -> Self {
        Self { gas_limit, blobs }
    }
}
