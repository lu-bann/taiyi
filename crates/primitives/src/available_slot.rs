use serde::{Deserialize, Serialize};

use crate::ProposerInfo;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct AvailableSlotResponse {
    pub current_slot: u64,
    pub current_epoch: u64,
    pub available_slots: Vec<ProposerInfo>,
}
