use luban_primitives::{PreconfHash, PreconfRequest};
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc, time::Instant};

/// OrderPool is a struct that holds the preconf requests and the time they were added to the pool.
///
/// It is responsible for
///  - adding/removing preconf requests to the pool
///  -
/// TODO: Clear old preconf requests
#[derive(Debug, Default)]
pub struct PreconfPool {
    //
    inner: Arc<RwLock<HashMap<PreconfHash, PreconfRequest>>>,
    //
    reqs_by_bn: HashMap<u64, Vec<PreconfRequest>>,
}

impl PreconfPool {
    /// Creates a new OrderPool.
    // pub fn new() -> Self {
    //     Self {
    //         preconf_reqs: HashMap::new(),
    //     }
    // }
    pub fn get(&self, key: &PreconfHash) -> Option<PreconfRequest> {
        self.inner.read().get(key).cloned()
    }

    /// Adds a preconf request to the pool.
    pub fn add_preconf_request(&self, preconf_req: PreconfRequest, bn: u64) {
        todo!()
        // add req to inner and reqs_by_bn
    }

    /// Removes a preconf request from the pool.
    pub fn remove_preconf_request(&mut self, preconf_req: PreconfRequest) {
        todo!()
    }

    pub fn exist(&self, key: &PreconfHash) -> bool {
        self.inner.read().get(key).is_some()
    }

    pub fn set(&self, key: PreconfHash, value: PreconfRequest) {
        self.inner.write().insert(key, value);
    }

    pub fn delete(&self, key: &PreconfHash) -> Option<PreconfRequest> {
        self.inner.write().remove(key)
    }

    /// Return preconf request for a given slot sorted by their tip
    pub fn sort_by_fee(&mut self, bn: u64) {
        self.reqs_by_bn
            .get_mut(&bn)
            .unwrap()
            .sort_by(|a, b| b.tip().cmp(&a.tip()));
    }

    /// Should be called when last block is updated
    pub fn head_updated(&mut self, new_block_number: u64) {
        // remove by target block
        self.reqs_by_bn
            .retain(|block_number, _| *block_number > new_block_number);
    }
}
