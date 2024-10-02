use std::sync::Arc;

use parking_lot::RwLock;
use taiyi_primitives::ProposerInfo;

#[derive(Debug, Clone, Default)]
pub struct NetworkState {
    current_epoch: Arc<RwLock<u64>>,
    current_slot: Arc<RwLock<u64>>,
    proposers: Arc<RwLock<Vec<ProposerInfo>>>,
}

impl NetworkState {
    pub fn new(current_epoch: u64, current_slot: u64, proposers: Vec<ProposerInfo>) -> Self {
        Self {
            current_epoch: Arc::new(RwLock::new(current_epoch)),
            current_slot: Arc::new(RwLock::new(current_slot)),
            proposers: Arc::new(RwLock::new(proposers)),
        }
    }

    pub fn get_current_epoch(&self) -> u64 {
        *self.current_epoch.read()
    }

    pub fn get_current_slot(&self) -> u64 {
        *self.current_slot.read()
    }

    pub fn get_proposer_duties(&self) -> Vec<ProposerInfo> {
        self.proposers.read().clone()
    }

    pub fn update_epoch(&self, epoch: u64) {
        *self.current_epoch.write() = epoch;
    }

    pub fn update_slot(&self, slot: u64) {
        *self.current_slot.write() = slot;
    }

    pub fn update_proposer_duties(&self, proposers: Vec<ProposerInfo>) {
        *self.proposers.write() = proposers;
    }

    #[allow(dead_code)]
    pub fn proposer_duty_for_slot(&self, slot: u64) -> Option<ProposerInfo> {
        self.proposers.read().iter().find(|duty| duty.slot == slot).cloned()
    }
}
