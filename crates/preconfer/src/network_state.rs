use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use alloy_primitives::Address;
use ethereum_consensus::deneb::Context;
use parking_lot::RwLock;

use crate::clients::relay_client::ValidatorSlotData;

#[derive(Clone)]
pub struct NetworkState {
    pub context: Context,
    /// Head slot
    current_slot: Arc<AtomicU64>,
    /// Available slots in current and next epochs
    available_slots: Arc<RwLock<Vec<u64>>>,
    /// Fee recipients for the current epoch and next epoch
    fee_receipients: Arc<RwLock<HashMap<u64, Address>>>,
}

impl NetworkState {
    pub fn new(context: Context) -> Self {
        Self {
            context,
            current_slot: Arc::new(AtomicU64::default()),
            available_slots: Arc::new(RwLock::new(vec![])),
            fee_receipients: Arc::new(RwLock::new(HashMap::new())),
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

    /// Update the fee recipients for the current & next epoch
    pub fn update_fee_recipients(&self, data: Vec<ValidatorSlotData>) {
        let mut fee_receipients = self.fee_receipients.write();
        fee_receipients.clear();
        data.into_iter().map(|data| (data.slot, data.entry.message.fee_recipient)).for_each(
            |(slot, recipient)| {
                fee_receipients.insert(slot, Address::from_slice(recipient.as_slice()));
            },
        );
    }
}
