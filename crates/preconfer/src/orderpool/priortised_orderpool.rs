#![allow(dead_code)]

use alloy::consensus::TxEnvelope;
use luban_primitives::PreconfRequest;
use parking_lot::RwLock;
use priority_queue::PriorityQueue;
use reth::primitives::{Address, B256, U256};
use std::{cmp::Ordering, collections::HashMap, sync::Arc};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OrderPriority {
    pub order_id: OrderId,
    pub priority: U256,
}

pub type OrderId = B256;

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
    /// Ready (all nonce matching (or not matched but optional)) to execute orders sorted
    main_queue: PriorityQueue<OrderId, OrderPriority>,
    /// For each account we store all the orders from main_queue which contain a tx from this account.
    /// Since the orders belong to main_queue these are orders ready to execute.
    /// As soon as we execute an order from main_queue all orders for all the accounts the order used (order.nonces()) could get invalidated (if tx is not optional).
    main_queue_nonces: HashMap<Address, Vec<OrderId>>,

    /// Up to date "onchain" nonces for the current block we are building.
    /// Special care must be taken to keep this in sync.
    onchain_nonces: HashMap<Address, u64>,

    /// Orders waiting for an account to reach a particular nonce.
    pending_orders: HashMap<AccountNonce, Vec<OrderId>>,
    /// Id -> order for all orders we manage. Carefully maintained by remove/insert
    orders_by_target_block: Arc<RwLock<HashMap<u64, Vec<PreconfRequest>>>>,
}

impl Default for PrioritizedOrderPool {
    fn default() -> Self {
        Self {
            main_queue: PriorityQueue::new(),
            main_queue_nonces: HashMap::default(),
            onchain_nonces: HashMap::default(),
            pending_orders: HashMap::default(),
            orders_by_target_block: Arc::new(RwLock::new(HashMap::default())),
        }
    }
}

impl PrioritizedOrderPool {
    /// Should be called when last block is updated
    pub fn head_updated(&mut self, new_block_number: u64) {
        // remove by target block
        self.orders_by_target_block
            .write()
            .retain(|block_number, _| *block_number > new_block_number);
    }

    pub fn insert_order(&mut self, order: PreconfRequest) {
        let order_id = B256::default();
        let target_block = order.preconf_conditions.block_number;
        if let Some(orders) = self.orders_by_target_block.read().get(&target_block) {
            if orders.contains(&order) {
                return;
            }
        }

        let onchain_nonce = U256::from(
            self.onchain_nonces
                .get(&order.tip_tx.from)
                .cloned()
                .unwrap_or_default(),
        );
        let account_nonce = order.nonce();

        // order can't be included
        if onchain_nonce > account_nonce {
            return;
        }

        let mut pending_nonce = None;
        if onchain_nonce < account_nonce {
            pending_nonce = Some(AccountNonce {
                account: order.tip_tx.from,
                nonce: onchain_nonce,
            });
        }

        if let Some(nonce) = &pending_nonce {
            // let pending = self.pending_orders.entry(nonce.clone()).or_default();
            // if !pending.contains(&order_id) {
            //     pending.push(order_id);
            // }
        } else {
            self.main_queue.push(
                order_id,
                OrderPriority {
                    priority: order.tip(),
                    order_id: order_id,
                },
            );
            self.main_queue_nonces
                .entry(order.tip_tx.from)
                .or_default()
                .push(order_id);
        }

        self.orders_by_target_block
            .write()
            .entry(target_block)
            .or_default()
            .push(order.clone());
    }

    pub fn pop_order(&mut self) -> Option<TxEnvelope> {
        unimplemented!()
    }

    // TODO: change this to return best constraints ready to be included in the block
    pub fn best_constraints_by_target_block(&self, target_block: u64) -> Vec<PreconfRequest> {
        self.orders_by_target_block
            .read()
            .get(&target_block)
            .cloned()
            .unwrap_or_default()
    }
}
