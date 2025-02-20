use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct SlotInfo {
    pub slot: u64,
    pub gas_available: u64,
    pub blobs_available: usize,
    pub constraints_available: u32,
}
