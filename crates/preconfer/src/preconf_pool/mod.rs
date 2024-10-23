pub mod parked;
pub mod pending;
pub mod ready;

use parked::Parked;
use pending::Pending;
use ready::Ready;
use taiyi_primitives::{PreconfHash, PreconfRequest};

use crate::{
    error::PoolError,
    validator::{PreconfValidator, ValidationOutcome},
};

/// A pool that manages preconf requests.
/// This pool maintains the state of all preconf requests and stores them accordingly.
#[derive(Debug, Clone)]
pub struct PreconfPool {
    /// Holds all parked preconf requests that depend on external changes from the sender:
    ///
    ///    - blocked by missing ancestor transaction (has nonce gaps)
    ///    - blocked by missing PreconfTx in preconf request
    parked: Parked,
    /// Holds all preconf requests that are ready to be included in the future slot.
    pending: Pending,
    /// Holds all preconf requests that are ready to be included in the next slot.
    ready: Ready,
    /// Pool settings to enforce limits etc.
    config: PoolConfig,
    /// Validator to validate preconf requests.
    validator: PreconfValidator,
}

impl PreconfPool {
    pub fn new(max_gas: u64, current_slot: u64, validator: PreconfValidator) -> Self {
        Self {
            parked: Parked::new(),
            pending: Pending::new(),
            ready: Ready::new(current_slot),
            config: PoolConfig::new(max_gas),
            validator,
        }
    }

    pub fn request_inclusion(
        &mut self,
        preconf_req: PreconfRequest,
    ) -> Result<PoolState, PoolError> {
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
    pub fn preconf_requests(&mut self) -> Result<Vec<PreconfRequest>, PoolError> {
        self.ready.preconf_requests()
    }

    /// Inserts a preconf request into the parked pool.
    fn insert_parked(&mut self, preconf_hash: PreconfHash, preconf_request: PreconfRequest) {
        self.parked.insert(preconf_hash, preconf_request);
    }

    /// Inserts a preconf request into the pending pool.
    fn insert_pending(&mut self, preconf_hash: PreconfHash, preconf_request: PreconfRequest) {
        self.pending.insert(preconf_hash, preconf_request);
    }

    /// Inserts a preconf request into the ready pool.
    fn insert_ready(&mut self, preconf_hash: PreconfHash, preconf_request: PreconfRequest) {
        self.ready.insert_order(preconf_hash, preconf_request);
    }

    /// Returns a preconf request from the parked pool.
    pub fn get_parked(&self, preconf_hash: &PreconfHash) -> Option<PreconfRequest> {
        self.parked.get(preconf_hash)
    }

    /// Deletes a preconf request from the parked pool.
    pub fn delete_parked(&mut self, preconf_hash: &PreconfHash) -> Option<PreconfRequest> {
        self.parked.remove(preconf_hash)
    }

    /// Returns the pool where the preconf request is currently in.
    pub fn get_pool(&self, preconf_hash: &PreconfHash) -> Result<PoolState, PoolError> {
        if self.parked.contains(preconf_hash) {
            Ok(PoolState::Parked)
        } else if self.pending.contains(preconf_hash) {
            Ok(PoolState::Pending)
        } else if self.ready.contains(preconf_hash) {
            Ok(PoolState::Ready)
        } else {
            Err(PoolError::PreconfRequestNotFound(*preconf_hash))
        }
    }

    pub fn slot_updated(&mut self, new_slot: u64) {
        // Moves preconf requests from pending to ready pool for which target slot is new slot + 1
        let preconfs =
            self.pending.on_new_slot(new_slot + 1).expect("Failed to update pending pool");
        for (preconf_hash, preconf_request) in preconfs {
            self.insert_ready(preconf_hash, preconf_request);
        }
        self.ready.update_slot(new_slot);
    }
}

#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum gas limit that can be included in a single slot.
    pub max_gas_per_slot: u64,
}

impl PoolConfig {
    pub fn new(max_gas: u64) -> Self {
        Self { max_gas_per_slot: max_gas }
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

//     use super::PreconfPool;

//     // FIXME
//     #[tokio::test]
//     #[ignore]
//     async fn test_prevalidate_req() {
//         let anvil = Anvil::new().block_time(1).chain_id(1).spawn();
//         let mut preconf_pool = PreconfPool::new(1_000_000_000, 1);
//         let sender = anvil.addresses().first().unwrap();
//         let receiver = anvil.addresses().last().unwrap();
//         let client = ClientBuilder::default().http(anvil.endpoint_url().into());

//         let slot: U64 = client.request("eth_blockNumber", ()).await.unwrap();
//         preconf_pool.slot_updated(slot.to());

//         let signer: PrivateKeySigner = anvil.keys()[0].clone().into();

//         let tip_tx = TipTransaction {
//             gas_limit: U256::from(1000),
//             from: sender.clone(),
//             to: receiver.clone(),
//             pre_pay: U256::from(1),
//             after_pay: U256::from(1),
//             nonce: U256::from(1),
//             target_slot: U256::from(slot.to::<u64>() + 2),
//         };
//         let tip_tx_signature = signer
//             .sign_hash(&keccak256(&tip_tx.tip_tx_hash(U256::from(anvil.chain_id()))))
//             .await
//             .unwrap();

//         let preconf_request = PreconfRequest {
//             tip_tx,
//             tip_tx_signature,
//             preconfer_signature: None,
//             preconf_tx: None,
//             preconf_req_signature: None,
//         };
//         assert!(preconf_pool.prevalidate_req(1, &preconf_request).is_ok());

//         // Add the same preconf request again
//         preconf_pool.insert_parked(preconf_request.hash(U256::from(1)), preconf_request.clone());
//         assert!(preconf_pool.prevalidate_req(1, &preconf_request).is_err());

//         // Add a preconf request with slot less than current slot
//         tokio::time::sleep(std::time::Duration::from_secs(5)).await;
//         assert!(preconf_pool.prevalidate_req(1, &preconf_request).is_err());
//     }
// }
