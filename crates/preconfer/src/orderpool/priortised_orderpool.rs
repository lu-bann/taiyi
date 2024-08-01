use std::{cmp::Ordering, collections::HashMap, sync::Arc};

use alloy::consensus::TxEnvelope;
use luban_primitives::PreconfRequest;
use parking_lot::RwLock;
use priority_queue::PriorityQueue;
use reth::primitives::{Address, B256};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OrderPriority {
    pub order_id: OrderId,
    pub priority: u128,
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
    pub nonce: u64,
    pub account: Address,
}
impl AccountNonce {
    pub fn with_nonce(self, nonce: u64) -> Self {
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

    pub fn insert(&self, order: PreconfRequest) {
        let bn = order.preconf_conditions.block_number;
        self.orders_by_target_block
            .write()
            .entry(bn)
            .or_default()
            .push(order);
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
