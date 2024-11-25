use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use alloy_eips::merge::EPOCH_SLOTS;
use ethereum_consensus::deneb::Context;
use parking_lot::RwLock;

#[derive(Clone)]
pub struct NetworkState {
    context: Context,
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

    pub fn get_context(&self) -> Context {
        self.context.clone()
    }

    pub fn get_current_epoch(&self) -> u64 {
        self.current_slot.load(Ordering::Relaxed) / EPOCH_SLOTS
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
}
