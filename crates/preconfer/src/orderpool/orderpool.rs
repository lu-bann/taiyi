use lru::LruCache;
use luban_primitives::{PreconfHash, PreconfRequest};
use parking_lot::RwLock;
use std::{collections::HashMap, num::NonZeroUsize, sync::Arc};

/// OrderPool is a temporary pool that holds the preconf requests
///
/// It is responsible for
///  - adding/removing preconf requests to the pool
///  -
#[derive(Debug)]
pub struct OrderPool {
    known_orders: Arc<RwLock<HashMap<PreconfHash, PreconfRequest>>>,
}

impl Default for OrderPool {
    fn default() -> Self {
        Self::new()
    }
}

impl OrderPool {
    pub fn new() -> Self {
        Self {
            known_orders: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn get(&self, key: &PreconfHash) -> Option<PreconfRequest> {
        self.known_orders.read().get(key).cloned()
    }

    pub fn exist(&self, key: &PreconfHash) -> bool {
        self.known_orders.read().get(key).is_some()
    }

    pub fn set(&self, key: PreconfHash, value: PreconfRequest) {
        self.known_orders.write().insert(key, value);
    }

    pub fn delete(&self, key: &PreconfHash) -> Option<PreconfRequest> {
        self.known_orders.write().remove(key)
    }
}
