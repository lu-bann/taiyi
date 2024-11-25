use std::collections::HashMap;

use taiyi_primitives::PreconfRequest;
use uuid::Uuid;

/// A pool of transactions that are currently parked and are waiting for external changes (e.g.
/// basefee, ancestor transactions, balance) that eventually move the transaction into the pending
/// pool.
#[derive(Debug, Clone)]
pub struct Parked {
    by_hash: HashMap<Uuid, PreconfRequest>,
}

impl Parked {
    pub fn new() -> Self {
        Self { by_hash: HashMap::new() }
    }

    pub fn get(&self, key: Uuid) -> Option<PreconfRequest> {
        self.by_hash.get(&key).cloned()
    }

    pub fn contains(&self, key: Uuid) -> bool {
        self.by_hash.contains_key(&key)
    }

    pub fn insert(&mut self, key: Uuid, value: PreconfRequest) {
        self.by_hash.insert(key, value);
    }

    pub fn remove(&mut self, key: Uuid) -> Option<PreconfRequest> {
        self.by_hash.remove(&key)
    }
}

#[cfg(test)]
mod tests {
    use taiyi_primitives::{BlockspaceAllocation, PreconfRequest};
    use uuid::Uuid;

    use super::Parked;

    #[test]
    fn test_add_remove_request() {
        let mut parked = Parked::new();
        let preconf = PreconfRequest {
            allocation: BlockspaceAllocation::default(),
            transaction: None,
            target_slot: 1,
        };

        let id = Uuid::new_v4();
        parked.insert(id, preconf.clone());
        assert!(parked.contains(id));
        assert_eq!(parked.get(id), Some(preconf.clone()));

        parked.remove(id);
        assert_eq!(parked.get(id), None);
    }
}
