#![allow(dead_code)]
use luban_primitives::{PreconfHash, PreconfRequest};
use std::collections::HashMap;

/// OrderPool is a temporary pool that holds the preconf requests
///
/// It is responsible for
///  - adding/removing preconf requests to the pool
///  
/// Preconf should be stored here until target_block is reached. Once target_block is reached, we validate and move all the preconf reqs for the target_block to the PrioritizedOrderPool
#[derive(Debug)]
pub struct OrderPool {
    known_orders: HashMap<PreconfHash, PreconfRequest>,
    orders_by_target_block: HashMap<u64, Vec<PreconfHash>>,
}

impl Default for OrderPool {
    fn default() -> Self {
        Self::new()
    }
}

impl OrderPool {
    pub fn new() -> Self {
        Self {
            known_orders: HashMap::new(),
            orders_by_target_block: HashMap::new(),
        }
    }

    pub fn get(&self, key: &PreconfHash) -> Option<PreconfRequest> {
        self.known_orders.get(key).cloned()
    }

    pub fn exist(&self, key: &PreconfHash) -> bool {
        self.known_orders.contains_key(key)
    }

    pub fn set(&mut self, key: PreconfHash, value: PreconfRequest) {
        self.known_orders.insert(key, value);
    }

    pub fn delete(&mut self, key: &PreconfHash) -> Option<PreconfRequest> {
        self.known_orders.remove(key)
    }
}
