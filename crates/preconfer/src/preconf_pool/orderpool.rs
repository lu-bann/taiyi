use luban_primitives::{PreconfHash, PreconfRequest};
use std::collections::HashMap;

use crate::preconf_api::state::MAX_COMMITMENTS_PER_SLOT;

// Currently set to Helder block gas limit
pub const MAX_GAS_PER_SLOT: u64 = 25_000_000;

/// OrderPool is a temporary pool that holds the preconf requests
///
/// It is responsible for
///  - adding/removing preconf requests to the pool
///  
/// Preconf should be stored here until target_block is reached. Once target_block is reached, we validate and move all the preconf reqs for the target_block to the PrioritizedOrderPool
#[derive(Debug, Clone)]
pub struct OrderPool {
    known_orders: HashMap<PreconfHash, PreconfRequest>,
    orders_by_target_slot: HashMap<u64, Vec<PreconfHash>>,
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
            orders_by_target_slot: HashMap::new(),
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

    pub fn head_updated(&mut self, new_slot: u64) {
        self.known_orders
            .retain(|_, order| order.preconf_conditions.slot >= new_slot);
        self.orders_by_target_slot
            .retain(|slot, _| *slot >= new_slot);
    }

    pub fn is_full(&self, target_block: u64) -> bool {
        self.orders_by_target_slot
            .get(&target_block)
            .map_or(false, |v| v.len() >= MAX_COMMITMENTS_PER_SLOT)
    }

    pub fn commited_gas(&self, target_block: u64) -> u64 {
        self.orders_by_target_slot
            .get(&target_block)
            .map_or(0, |v| {
                v.iter()
                    .filter_map(|hash| self.known_orders.get(hash))
                    .map(|order| order.tip_tx.gas_limit.to::<u64>())
                    .sum()
            })
    }
}
