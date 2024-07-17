use std::ops::Deref;

use beacon_api_client::ProposerDuty;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AvailableSlotResponse {
    pub current_slot: u64,
    pub available_slots: Vec<ProposerDuty>,
}

impl Clone for AvailableSlotResponse {
    fn clone(&self) -> Self {
        let mut available_slots = Vec::with_capacity(32);

        for duty in self.available_slots.iter() {
            available_slots.push(ProposerDuty {
                public_key: duty
                    .public_key
                    .deref()
                    .as_ref()
                    .try_into()
                    .expect("Invalid public key"),
                validator_index: duty.validator_index,
                slot: duty.slot,
            });
        }
        AvailableSlotResponse {
            current_slot: self.current_slot,
            available_slots,
        }
    }
}
