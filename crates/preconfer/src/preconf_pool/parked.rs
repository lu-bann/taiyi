use std::collections::HashMap;

use taiyi_primitives::{PreconfHash, PreconfRequest};

/// A pool of transactions that are currently parked and are waiting for external changes (e.g.
/// basefee, ancestor transactions, balance) that eventually move the transaction into the pending
/// pool.
#[derive(Debug, Clone)]
pub struct Parked {
    by_hash: HashMap<PreconfHash, PreconfRequest>,
}

impl Parked {
    pub fn new() -> Self {
        Self { by_hash: HashMap::new() }
    }

    pub fn get(&self, key: &PreconfHash) -> Option<PreconfRequest> {
        self.by_hash.get(key).cloned()
    }

    pub fn contains(&self, key: &PreconfHash) -> bool {
        self.by_hash.contains_key(key)
    }

    pub fn insert(&mut self, key: PreconfHash, value: PreconfRequest) {
        self.by_hash.insert(key, value.clone());
    }

    pub fn remove(&mut self, key: &PreconfHash) -> Option<PreconfRequest> {
        self.by_hash.remove(key)
    }
}
