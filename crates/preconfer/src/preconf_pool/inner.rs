use std::collections::HashMap;

use alloy_eips::{eip1559::ETHEREUM_BLOCK_GAS_LIMIT, eip4844::MAX_BLOBS_PER_BLOCK};
use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

use crate::preconf_pool::{Pending, Ready};

/// Inner type containing all sub-pools
#[derive(Debug)]
pub struct PreconfPoolInner {
    /// Stores requests without preconf transactions.
    pub pending: Pending,
    /// Stores requests with preconf transactions.
    pub ready: Ready,
    /// Blockspace issued for every slot is tracked here.
    pub blockspace_issued: HashMap<u64, BlockspaceAvailable>,
}

impl PreconfPoolInner {
    pub fn escrow_balance_diffs(&self, account: Address) -> Option<U256> {
        let pending_diff = self.pending.get_balance_diffs_for_account(account);
        let ready_diff = self.ready.get_balance_diffs_for_account(account);

        match (pending_diff, ready_diff) {
            (Some(pending_diff), Some(ready_diff)) => Some(pending_diff + ready_diff),
            (Some(pending_diff), None) => Some(pending_diff),
            (None, Some(ready_diff)) => Some(ready_diff),
            (None, None) => None,
        }
    }

    pub fn update_blockspace(&mut self, slot: u64, blockspace: BlockspaceAvailable) {
        self.blockspace_issued.insert(slot, blockspace);
    }

    pub fn has_preconf_requests(&self, account: Address) -> bool {
        self.pending.has_preconf_requests(account) || self.ready.has_preconf_requests(account)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockspaceAvailable {
    pub gas_limit: u64,
    pub blobs: usize,
    pub num_of_constraints: u32,
}

impl Default for BlockspaceAvailable {
    fn default() -> Self {
        Self {
            gas_limit: ETHEREUM_BLOCK_GAS_LIMIT,
            blobs: MAX_BLOBS_PER_BLOCK,
            num_of_constraints: 256,
        }
    }
}
