use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use alloy_primitives::{hex::FromHex, FixedBytes, B256};
use ethereum_consensus::deneb::Context;
use parking_lot::RwLock;

#[derive(Clone)]
pub struct NetworkState {
    pub context: Context,
    current_slot: Arc<AtomicU64>,
    available_slots: Arc<RwLock<Vec<u64>>>,
}

impl NetworkState {
    pub fn new(context: Context) -> Self {
        Self {
            context,
            current_slot: Arc::new(AtomicU64::default()),
            available_slots: Arc::new(RwLock::new(vec![])),
        }
    }

    pub fn chain_id(&self) -> u64 {
        self.context.deposit_chain_id as u64
    }

    pub fn context(&self) -> Context {
        self.context.clone()
    }

    pub fn get_current_epoch(&self) -> u64 {
        self.current_slot.load(Ordering::Relaxed) / self.context.slots_per_epoch
    }

    pub fn get_current_slot(&self) -> u64 {
        self.current_slot.load(Ordering::Relaxed)
    }

    pub fn update_slot(&self, slot: u64) {
        self.current_slot.store(slot, Ordering::Relaxed);
    }

    pub fn add_slot(&self, slot: u64) {
        self.available_slots.write().push(slot);
    }

    pub fn available_slots(&self) -> Vec<u64> {
        self.available_slots.read().clone()
    }

    /// Removes the slots which are older than epoch head slot
    pub fn clear_slots(&self, epoch: u64) {
        let mut available_slots = self.available_slots.write();
        available_slots.retain(|&slot| slot >= epoch * self.context.slots_per_epoch);
    }

    pub fn contains_slot(&self, slot: u64) -> bool {
        self.available_slots.read().contains(&slot)
    }
}
