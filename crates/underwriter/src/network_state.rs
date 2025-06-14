use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use alloy_primitives::Address;
use parking_lot::RwLock;

use crate::clients::relay_client::ValidatorSlotData;

pub const SET_CONSTRAINTS_CUTOFF_S: u64 = 8;
pub const SET_CONSTRAINTS_CUTOFF_DELTA_S: u64 = 1;

#[derive(Clone)]
pub struct NetworkState {
    seconds_per_slot: u64,
    slots_per_epoch: u64,
    chain_id: u64,
    genesis_time: u64,
    /// Head slot
    current_slot: Arc<AtomicU64>,
    /// Available slots in current and next epochs
    available_slots: Arc<RwLock<Vec<u64>>>,
    /// Fee recipients for the current epoch and next epoch
    fee_receipients: Arc<RwLock<HashMap<u64, Address>>>,
}

impl NetworkState {
    pub fn new(
        seconds_per_slot: u64,
        slots_per_epoch: u64,
        chain_id: u64,
        genesis_time: u64,
    ) -> Self {
        Self {
            seconds_per_slot,
            slots_per_epoch,
            chain_id,
            genesis_time,
            current_slot: Arc::new(AtomicU64::default()),
            available_slots: Arc::new(RwLock::new(vec![])),
            fee_receipients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn seconds_per_slot(&self) -> u64 {
        self.seconds_per_slot
    }

    pub fn slots_per_epoch(&self) -> u64 {
        self.slots_per_epoch
    }

    pub fn get_current_epoch(&self) -> u64 {
        self.current_slot.load(Ordering::Relaxed) / self.slots_per_epoch
    }

    pub fn get_current_slot(&self) -> u64 {
        self.current_slot.load(Ordering::Relaxed)
    }

    pub fn update_slot(&self, slot: u64) {
        // Update the current slot
        self.current_slot.store(slot, Ordering::Relaxed);
        // Remove the slots which are older than the given slot
        let mut available_slots = self.available_slots.write();
        available_slots.retain(|&s| s >= slot);
    }

    pub fn add_slot(&self, slot: u64) {
        self.available_slots.write().push(slot);
    }

    pub fn available_slots(&self) -> Vec<u64> {
        self.available_slots.read().clone()
    }

    pub fn contains_slot(&self, slot: u64) -> bool {
        self.available_slots.read().contains(&slot)
    }

    pub fn get_fee_recipient(&self, slot: u64) -> Option<Address> {
        self.fee_receipients.read().get(&slot).cloned()
    }

    pub fn update_fee_recipients(&self, data: Vec<ValidatorSlotData>) {
        let mut fee_receipients = self.fee_receipients.write();
        fee_receipients.clear();
        data.into_iter().map(|data| (data.slot, data.entry.message.fee_recipient)).for_each(
            |(slot, recipient)| {
                fee_receipients.insert(slot, Address::from_slice(recipient.as_slice()));
            },
        );
    }

    pub fn get_deadline_of_slot(&self, slot: u64) -> u64 {
        let genesis_time = self.genesis_time();
        genesis_time + ((slot - 1) * self.seconds_per_slot) + SET_CONSTRAINTS_CUTOFF_S
            - SET_CONSTRAINTS_CUTOFF_DELTA_S
    }

    pub fn genesis_time(&self) -> u64 {
        self.genesis_time
    }
}
