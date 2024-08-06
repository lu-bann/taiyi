#![allow(dead_code)]

use luban_primitives::{PreconfHash, PreconfRequest};
use priority_queue::PriorityQueue;
use reth::primitives::{Address, U256};
use std::{cmp::Ordering, collections::HashMap};

use crate::reth_db_utils::state::AccountState;

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
impl AccountNonce {
    pub fn with_nonce(self, nonce: U256) -> Self {
        AccountNonce {
            account: self.account,
            nonce,
        }
    }
}

/// Orders are validated after the user sends the full transaction.
/// Valid orders are stored in the order store.
///
/// TDOD: Doc
#[derive(Debug, Clone)]
pub struct PrioritizedOrderPool {
    main_queue: PriorityQueue<OrderId, OrderPriority>,
    pub canonical_state: HashMap<Address, AccountState>,
    pub intermediate_state: HashMap<Address, (U256, u64)>,
    /// Id -> order for all orders we manage. Carefully maintained by remove/insert
    orders: HashMap<OrderId, PreconfRequest>,
}

impl Default for PrioritizedOrderPool {
    fn default() -> Self {
        Self {
            main_queue: PriorityQueue::new(),
            canonical_state: HashMap::default(),
            intermediate_state: HashMap::default(),
            orders: HashMap::default(),
        }
    }
}

impl PrioritizedOrderPool {

    pub fn insert_order(&mut self, order_id: PreconfHash, order: PreconfRequest) {
        if self.orders.contains_key(&order_id) {
            return;
        }

        self.main_queue.push(
            order_id,
            OrderPriority {
                priority: order.tip(),
                order_id: order_id,
            },
        );

        self.orders.insert(order_id, order.clone());

        self.intermediate_state
            .entry(order.tip_tx.from)
            .and_modify(|(balance, nonce)| {
                *balance += order.tip_tx.pre_pay + order.tip_tx.after_pay;
                *nonce += 1;
            });
    }

    pub fn pop_order(&mut self) -> Option<PreconfRequest> {
        let (id, _) = self.main_queue.pop()?;
        self.orders.remove(&id)
    }

    pub fn transaction_size(&self) -> usize {
        self.main_queue.len()
    }
}
