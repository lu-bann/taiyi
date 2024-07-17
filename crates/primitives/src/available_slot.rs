use beacon_api_client::ProposerDuty;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AvailableSlotResponse {
    pub current_slot: u64,
    pub available_slots: Vec<ProposerDuty>,
}

