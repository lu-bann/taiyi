use alloy_primitives::PrimitiveSignature;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PreconfResponseData {
    pub request_id: Uuid,
    pub commitment: Option<PrimitiveSignature>,
    pub sequence_num: Option<u64>,
    /// current slot at the time of response
    pub current_slot: u64,
}

impl PreconfResponseData {
    pub fn success(
        request_id: Uuid,
        commitment: Option<PrimitiveSignature>,
        sequence_num: Option<u64>,
        current_slot: u64,
    ) -> Self {
        PreconfResponseData { request_id, commitment, sequence_num, current_slot }
    }
}
