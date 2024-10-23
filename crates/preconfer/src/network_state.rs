use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use alloy_eips::merge::EPOCH_SLOTS;
use parking_lot::RwLock;
use taiyi_primitives::ProposerInfo;

#[derive(Debug, Clone, Default)]
pub struct NetworkState {
    current_slot: Arc<AtomicU64>,
    proposers: Arc<RwLock<Vec<ProposerInfo>>>,
}

impl NetworkState {
    pub fn new(current_slot: u64, proposers: Vec<ProposerInfo>) -> Self {
        Self {
            current_slot: Arc::new(AtomicU64::new(current_slot)),
            proposers: Arc::new(RwLock::new(proposers)),
        }
    }

    pub fn get_current_epoch(&self) -> u64 {
        self.current_slot.load(Ordering::Relaxed) / EPOCH_SLOTS
    }

    pub fn get_current_slot(&self) -> u64 {
        self.current_slot.load(Ordering::Relaxed)
    }

    pub fn get_proposer_duties(&self) -> Vec<ProposerInfo> {
        self.proposers.read().clone()
    }

    pub fn update_slot(&self, slot: u64) {
        self.current_slot.store(slot, Ordering::Relaxed);
    }

    pub fn update_proposer_duties(&self, proposers: Vec<ProposerInfo>) {
        *self.proposers.write() = proposers;
    }

    pub fn _proposer_duty_for_slot(&self, slot: u64) -> Option<ProposerInfo> {
        self.proposers.read().iter().find(|duty| duty.slot == slot).cloned()
    }
}
