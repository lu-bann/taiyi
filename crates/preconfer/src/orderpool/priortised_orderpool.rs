use std::{cmp::Ordering, collections::HashMap, sync::Arc};

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
/// Duties:
///     - Validate the order
///     -
/// Order store that checks the nonces and priorities of the orders so we can easily get the best by calling pop_order()
/// Not orders are ready to be executed due to nonce dependencies.
/// Order must implement BlockOrdersOrder which has priority(). This priority is used to sort the simulated orders.
/// Usage:
/// - Add new order (a little bit complex):
///     ALWAYS BE SURE THAT YOU CALLED update_onchain_nonces and updated the current state of all the needed nonces by the order
///     call insert_order
/// - Get best order to execute
///     call pop_order to get the best order
///     if the order is executed call update_onchain_nonces to update all the changed nonces.
/// - Remove orders: remove_orders. This is useful if we think this orders are no really good (failed to execute to often)
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
        self.orders_by_target_block.write()
            .retain(|block_number, _| *block_number > new_block_number);
    }

    pub fn insert(&self, order: PreconfRequest) {
        let bn = order.preconf_conditions.block_number;
        self.orders_by_target_block.write()
            .entry(bn)
            .or_default()
            .push(order);
    }

    // pub fn new(onchain_nonces: HashMap<Address, u64>) -> Self {
    //     Self {
    //         main_queue: PriorityQueue::new(),
    //         main_queue_nonces: HashMap::default(),
    //         onchain_nonces,
    //         pending_orders: HashMap::default(),
    //         orders_by_target_block: HashMap::default(),
    //     }
    // }

    // pub fn pop_order(&mut self) -> Option<SimulatedOrder> {
    //     let (id, _) = self.main_queue.pop()?;

    //     let order = self
    //         .remove_poped_order(&id)
    //         .expect("order from prio queue not found in block orders");
    //     Some(order)
    // }

    // /// Clean up after some order was removed from main_queue
    // fn remove_poped_order(&mut self, id: &OrderId) -> Option<SimulatedOrder> {
    //     let sim_order = self.orders.remove(id)?;
    //     for Nonce { address, .. } in sim_order.order.nonces() {
    //         match self.main_queue_nonces.entry(address) {
    //             Entry::Occupied(mut entry) => {
    //                 entry.get_mut().retain(|id| *id != sim_order.id());
    //             }
    //             Entry::Vacant(_) => {}
    //         }
    //     }
    //     Some(sim_order)
    // }

    // // if order updates onchain nonce from n -> n + 2, we get n + 2 as an arguments here
    // pub fn update_onchain_nonces(&mut self, new_nonces: &[AccountNonce]) {
    //     let mut invalidated_orders = HashSet::default();
    //     for new_nonce in new_nonces {
    //         self.onchain_nonces
    //             .insert(new_nonce.account, new_nonce.nonce);

    //         let orders = if let Some(orders) = self.main_queue_nonces.remove(&new_nonce.account) {
    //             orders
    //         } else {
    //             continue;
    //         };
    //         for order_id in orders {
    //             invalidated_orders.insert(order_id);
    //         }
    //     }

    //     for order_id in invalidated_orders {
    //         // check if order can still be valid because of optional nonces

    //         self.main_queue.remove(&order_id);
    //         let order = self
    //             .remove_poped_order(&order_id)
    //             .expect("order from prio queue not found in block orders");
    //         let mut valid = true;
    //         let mut valid_nonces = 0;
    //         for Nonce {
    //             nonce,
    //             address,
    //             optional,
    //         } in order.nonces()
    //         {
    //             let onchain_nonce = self
    //                 .onchain_nonces
    //                 .get(&address)
    //                 .cloned()
    //                 .unwrap_or_default();
    //             if onchain_nonce > nonce && !optional {
    //                 valid = false;
    //                 break;
    //             } else if onchain_nonce == nonce {
    //                 valid_nonces += 1;
    //             }
    //         }
    //         let retain_order = valid && valid_nonces > 0;
    //         tracing::trace!(
    //             "invalidated order: {:?}, retain: {}",
    //             order_id,
    //             retain_order
    //         );
    //         if retain_order {
    //             self.insert_order(order);
    //         }
    //     }

    //     for new_nonce in new_nonces {
    //         if let Some(pending) = self.pending_orders.remove(new_nonce) {
    //             let orders = pending
    //                 .iter()
    //                 .filter_map(|id| self.orders.remove(id))
    //                 .collect::<Vec<_>>();
    //             for order in orders {
    //                 self.insert_order(order);
    //             }
    //         }
    //     }
    // }

    // // pub fn get_all_orders(&self) -> Vec<SimulatedOrder> {
    // //     self.orders.values().cloned().collect()
    // // }

    // fn insert_order(&mut self, sim_order: SimulatedOrder) {
    //     if self.orders.contains_key(&sim_order.id()) {
    //         return;
    //     }
    //     let mut pending_nonces = Vec::new();
    //     for Nonce {
    //         nonce,
    //         address,
    //         optional,
    //     } in sim_order.nonces()
    //     {
    //         let onchain_nonce = self
    //             .onchain_nonces
    //             .get(&address)
    //             .cloned()
    //             .unwrap_or_default();
    //         if onchain_nonce > nonce && !optional {
    //             // order can't be included because of nonce
    //             return;
    //         }
    //         if onchain_nonce < nonce && !optional {
    //             pending_nonces.push(AccountNonce {
    //                 account: address,
    //                 nonce,
    //             });
    //         }
    //     }
    //     if pending_nonces.is_empty() {
    //         self.main_queue.push(
    //             sim_order.id(),
    //             OrderPriority {
    //                 priority: self
    //                     .priority
    //                     .sorting_value(&sim_order.sim_value)
    //                     .to::<u128>(),
    //                 order_id: sim_order.id(),
    //             },
    //         );
    //         for nonce in sim_order.nonces() {
    //             self.main_queue_nonces
    //                 .entry(nonce.address)
    //                 .or_default()
    //                 .push(sim_order.id());
    //         }
    //     } else {
    //         for pending_nonce in pending_nonces {
    //             let pending = self.pending_orders.entry(pending_nonce).or_default();
    //             if !pending.contains(&sim_order.id()) {
    //                 pending.push(sim_order.id());
    //             }
    //         }
    //     }
    //     self.orders.insert(sim_order.id(), sim_order);
    // }

    // fn remove_order(&mut self, id: OrderId) -> Option<SimulatedOrder> {
    //     // we don't remove from pending because pending will clean itself
    //     if self.main_queue.remove(&id).is_some() {
    //         self.remove_poped_order(&id);
    //     }
    //     self.orders.remove(&id)
    // }
}
