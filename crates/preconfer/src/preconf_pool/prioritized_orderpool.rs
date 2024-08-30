use alloy_primitives::{Address, U256};
use ethereum_consensus::ssz::prelude::List;
use luban_primitives::{Constraint, ConstraintsMessage, PreconfHash, PreconfRequest};
use priority_queue::PriorityQueue;
use std::{cmp::Ordering, collections::HashMap};

use crate::{error::OrderPoolError, rpc_state::AccountState};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OrderPriority {
    pub order_id: OrderId,
    pub priority: U256,
}

pub type OrderId = PreconfHash;

impl PartialOrd for OrderPriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrderPriority {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority
            .cmp(&other.priority)
            .then_with(|| self.order_id.cmp(&other.order_id))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct AccountNonce {
    pub nonce: U256,
    pub account: Address,
}

/// Orders are validated after the user sends the full transaction.
///
/// Only contains orders for which target_block is next slot
#[derive(Debug, Clone)]
pub struct PrioritizedOrderPool {
    main_queue: PriorityQueue<OrderId, OrderPriority>,
    pub canonical_state: HashMap<Address, AccountState>,
    pub intermediate_state: HashMap<Address, (U256, u64)>,
    /// Id -> order for all orders we manage. Carefully maintained by remove/insert
    orders: HashMap<OrderId, PreconfRequest>,
    // current slot
    pub slot: Option<u64>,
}

impl Default for PrioritizedOrderPool {
    fn default() -> Self {
        Self {
            main_queue: PriorityQueue::new(),
            canonical_state: HashMap::default(),
            intermediate_state: HashMap::default(),
            orders: HashMap::default(),
            slot: None,
        }
    }
}

impl PrioritizedOrderPool {
    pub fn insert_order(&mut self, order_id: PreconfHash, order: PreconfRequest) {
        if self.orders.contains_key(&order_id) {
            return;
        }

        if self.slot.is_none() {
            self.slot = Some(order.preconf_conditions.slot);
        }

        self.main_queue.push(
            order_id,
            OrderPriority {
                priority: order.tip(),
                order_id,
            },
        );

        self.orders.insert(order_id, order.clone());

        self.intermediate_state
            .entry(order.tip_tx.from)
            .and_modify(|(balance, nonce)| {
                // TODO balance should account for total transaction cost including gas costs
                *balance += order.tip_tx.pre_pay + order.tip_tx.after_pay;
                *nonce += 1;
            });
    }

    pub fn pop_order(&mut self) -> Option<PreconfRequest> {
        let (id, _) = self.main_queue.pop()?;
        self.orders.remove(&id)
    }

    pub fn constraints(&mut self) -> Result<ConstraintsMessage, OrderPoolError> {
        let mut preconfs = Vec::new();
        while !self.main_queue.is_empty() {
            let preconf = self.pop_order().ok_or(OrderPoolError::OrderPoolIsEmpty)?;
            let constraint = vec![Constraint::from(preconf)];
            let constraint_list = List::try_from(constraint).expect("constraint list");
            preconfs.push(constraint_list);
        }

        let slot = self
            .slot
            .ok_or(OrderPoolError::PrioritizedOrderPoolNotInitialized)?;
        let constraints = List::try_from(preconfs).expect("constraints");

        Ok(ConstraintsMessage { slot, constraints })
    }

    pub fn update_slot(&mut self, slot: u64) {
        self.slot = Some(slot);
    }
}
