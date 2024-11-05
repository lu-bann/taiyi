use std::sync::Arc;

use parked::Parked;
use parking_lot::RwLock;
use pending::Pending;
use ready::Ready;
use reth_revm::primitives::EnvKzgSettings;
use taiyi_primitives::{PreconfHash, PreconfRequest};
use tracing::{error, info};

use crate::{
    error::PoolError,
    validator::{constant::DEFAULT_MAX_TX_INPUT_BYTES, PreconfValidator, ValidationOutcome},
};

mod parked;
mod pending;
mod ready;

#[derive(Debug)]
pub struct PreconfPoolBuilder;

impl PreconfPoolBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(self, slot: u64) -> Arc<PreconfPool> {
        let validator = PreconfValidator::new(
            30_000_000,
            None,
            EnvKzgSettings::default(),
            DEFAULT_MAX_TX_INPUT_BYTES,
        );
        Arc::new(PreconfPool::new(slot, validator))
    }
}

/// A pool that manages preconf requests.
/// This pool maintains the state of all preconf requests and stores them accordingly.
#[derive(Debug)]
pub struct PreconfPool {
    /// Pool inner
    pool_inner: RwLock<PreconfPoolInner>,
    /// Validator to validate preconf requests.
    validator: PreconfValidator,
}

impl PreconfPool {
    pub fn new(current_slot: u64, validator: PreconfValidator) -> Self {
        Self {
            pool_inner: RwLock::new(PreconfPoolInner {
                parked: Parked::new(),
                pending: Pending::new(),
                ready: Ready::new(current_slot),
            }),
            validator,
        }
    }

    pub fn request_inclusion(&self, preconf_req: PreconfRequest) -> Result<PoolState, PoolError> {
        // validate the preconf request
        let validation_outcome = self.validator.validate(&preconf_req);

        match validation_outcome {
            ValidationOutcome::Valid { simulate, preconf_hash } => {
                if simulate {
                    // TODO: send the transaction to the simulator
                    self.insert_ready(preconf_hash, preconf_req);
                    Ok(PoolState::Ready)
                } else {
                    self.insert_pending(preconf_hash, preconf_req);
                    Ok(PoolState::Pending)
                }
            }
            ValidationOutcome::ParkedValid(preconf_hash) => {
                self.insert_parked(preconf_hash, preconf_req);
                Ok(PoolState::Parked)
            }
            ValidationOutcome::Invalid(preconf_hash) => {
                Err(PoolError::InvalidPreconfTx(preconf_hash))
            }
            ValidationOutcome::Error => Err(PoolError::InvalidPreconfRequest),
        }
    }

    /// Returns all preconf requests that are ready to be executed in the next block.
    pub fn preconf_requests(&self) -> Result<Vec<PreconfRequest>, PoolError> {
        self.pool_inner.write().ready.preconf_requests()
    }

    /// Inserts a preconf request into the parked pool.
    fn insert_parked(&self, preconf_hash: PreconfHash, preconf_request: PreconfRequest) {
        self.pool_inner.write().parked.insert(preconf_hash, preconf_request);
    }

    /// Inserts a preconf request into the pending pool.
    fn insert_pending(&self, preconf_hash: PreconfHash, preconf_request: PreconfRequest) {
        self.pool_inner.write().pending.insert(preconf_hash, preconf_request);
    }

    /// Inserts a preconf request into the ready pool.
    fn insert_ready(&self, preconf_hash: PreconfHash, preconf_request: PreconfRequest) {
        self.pool_inner.write().ready.insert_order(preconf_hash, preconf_request);
    }

    /// Returns a preconf request from the parked pool.
    pub fn get_parked(&self, preconf_hash: &PreconfHash) -> Option<PreconfRequest> {
        self.pool_inner.read().parked.get(preconf_hash)
    }

    /// Deletes a preconf request from the parked pool.
    pub fn delete_parked(&self, preconf_hash: &PreconfHash) -> Option<PreconfRequest> {
        self.pool_inner.write().parked.remove(preconf_hash)
    }

    /// Returns the pool where the preconf request is currently in.
    pub fn get_pool(&self, preconf_hash: &PreconfHash) -> Result<PoolState, PoolError> {
        let pool_inner = self.pool_inner.read();
        if pool_inner.parked.contains(preconf_hash) {
            Ok(PoolState::Parked)
        } else if pool_inner.pending.contains(preconf_hash) {
            Ok(PoolState::Pending)
        } else if pool_inner.ready.contains(preconf_hash) {
            Ok(PoolState::Ready)
        } else {
            Err(PoolError::PreconfRequestNotFound(*preconf_hash))
        }
    }

    #[allow(dead_code)]
    pub fn move_pending_to_ready(&self, slot: u64) {
        self.pool_inner.write().move_pending_to_ready(slot);
    }
}

#[derive(Debug)]
pub struct PreconfPoolInner {
    /// Holds all parked preconf requests that depend on external changes from the sender:
    ///
    ///    - blocked by missing ancestor transaction (has nonce gaps)
    ///    - blocked by missing PreconfTx in preconf request
    parked: Parked,
    /// Holds all preconf requests that are ready to be included in the future slot.
    pending: Pending,
    /// Holds all preconf requests that are ready to be included in the next slot.
    ready: Ready,
}

impl PreconfPoolInner {
    #[allow(dead_code)]
    pub fn move_pending_to_ready(&mut self, slot: u64) {
        let preconfs = match self.pending.remove_preconfs_for_slot(slot) {
            Ok(preconfs) => preconfs,
            Err(PoolError::SlotNotFound(slot)) => {
                info!("no preconf requests for slot {slot}");
                return;
            }
            Err(e) => {
                error!("failed to move pending to ready: {e}");
                return;
            }
        };
        for (preconf_hash, preconf_request) in preconfs {
            self.ready.insert_order(preconf_hash, preconf_request);
        }
        self.ready.update_slot(slot);
    }
}

#[derive(Debug, Clone)]
pub enum PoolState {
    Parked,
    Pending,
    Ready,
}

// #[cfg(test)]
// mod tests {
//     use alloy_node_bindings::Anvil;
//     use alloy_primitives::{keccak256, U256, U64};
//     use alloy_rpc_client::ClientBuilder;
//     use alloy_signer::Signer;
//     use alloy_signer_local::PrivateKeySigner;
//     use taiyi_primitives::{PreconfRequest, TipTransaction};

//     use super::*;

//     // FIXME
//     #[tokio::test]
//     #[ignore]
//     async fn test_validate() {
//     }
// }
