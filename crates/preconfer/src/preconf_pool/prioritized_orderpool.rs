#![allow(dead_code)]

use std::{cmp::Ordering, collections::HashMap};

use alloy_primitives::{Address, U256};
use priority_queue::PriorityQueue;
use taiyi_primitives::{PreconfHash, PreconfRequest};

use crate::error::OrderPoolError;

pub type OrderId = PreconfHash;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OrderPriority {
    pub order_id: OrderId,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct AccountNonce {
    pub nonce: U256,
    pub account: Address,
}

// Stores Preconfirmation requests containing PreconfTx
#[derive(Debug, Clone, Default)]
pub struct PrioritizedOrderPool {
    queue_by_target_slot: HashMap<u64, PriorityQueue<OrderId, OrderPriority>>,
    orders: HashMap<OrderId, PreconfRequest>,
    // pub canonical_state: HashMap<Address, AccountState>,
    // pub intermediate_state: HashMap<Address, (U256, u64)>,
}

impl PrioritizedOrderPool {
    pub fn insert_order(&mut self, order_id: PreconfHash, order: PreconfRequest) {
        if self.orders.contains_key(&order_id) {
            return;
        }

        let slot = order.target_slot().to();
        let priority = OrderPriority { order_id, priority: order.tip() };
        self.queue_by_target_slot.entry(slot).or_default().push(order_id, priority);

        self.orders.insert(order_id, order.clone());
    }

    pub fn fetch_preconf_requests_for_slot(
        &mut self,
        slot: u64,
    ) -> Result<Vec<PreconfRequest>, OrderPoolError> {
        let mut preconfs = Vec::new();
        let queue =
            self.queue_by_target_slot.get_mut(&slot).ok_or(OrderPoolError::OrderPoolIsEmpty)?;
        while !queue.is_empty() {
            let (order_id, _) = queue.pop().ok_or(OrderPoolError::OrderPoolIsEmpty)?;
            preconfs.push(self.orders.remove(&order_id).ok_or(OrderPoolError::OrderPoolIsEmpty)?);
        }

        Ok(preconfs)
    }
}
