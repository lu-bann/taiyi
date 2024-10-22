use std::{cmp::Ordering, collections::HashMap};

use alloy_primitives::U256;
use priority_queue::PriorityQueue;
use taiyi_primitives::{PreconfHash, PreconfRequest};

use crate::error::PoolError;

/// Only contains orders for which target slot is next current slot + 1
#[derive(Debug, Clone)]
pub struct Ready {
    main_queue: PriorityQueue<PreconfHash, OrderPriority>,
    orders: HashMap<PreconfHash, PreconfRequest>,
    // current slot
    slot: u64,
}

impl Ready {
    pub fn new(slot: u64) -> Self {
        Self { main_queue: PriorityQueue::new(), orders: HashMap::default(), slot }
    }

    pub fn contains(&self, key: &PreconfHash) -> bool {
        self.orders.contains_key(key)
    }

    pub fn insert_order(&mut self, order_id: PreconfHash, order: PreconfRequest) {
        if self.orders.contains_key(&order_id) {
            return;
        }
        self.main_queue.push(order_id, OrderPriority { priority: order.tip(), order_id });
        self.orders.insert(order_id, order.clone());
    }

    pub fn pop_order(&mut self) -> Option<PreconfRequest> {
        let (id, _) = self.main_queue.pop()?;
        self.orders.remove(&id)
    }

    pub fn preconf_requests(&mut self) -> Result<Vec<PreconfRequest>, PoolError> {
        let mut preconfs = Vec::new();
        while !self.main_queue.is_empty() {
            let preconf_request = self.pop_order().ok_or(PoolError::OrderPoolIsEmpty)?;
            preconfs.push(preconf_request);
        }
        Ok(preconfs)
    }

    pub fn update_slot(&mut self, slot: u64) {
        self.slot = slot;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OrderPriority {
    pub order_id: PreconfHash,
    pub priority: U256,
}

impl PartialOrd for OrderPriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrderPriority {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority.cmp(&other.priority).then_with(|| self.order_id.cmp(&other.order_id))
    }
}
