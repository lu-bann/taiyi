use alloy_primitives::PrimitiveSignature;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PreconfResponse {
    pub status: String,
    pub message: String,
    pub data: PreconfResponseData,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PreconfResponseData {
    pub request_id: Uuid,
    pub commitment: Option<PrimitiveSignature>,
    pub sequence_num: Option<u64>,
}

impl PreconfResponse {
    pub fn success(
        request_id: Uuid,
        commitment: Option<PrimitiveSignature>,
        sequence_num: Option<u64>,
    ) -> Self {
        Self {
            status: "success".to_string(),
            message:
                "Your preconf request has been successfully received and is pending processing."
                    .to_string(),
            data: PreconfResponseData { request_id, commitment, sequence_num },
        }
    }
}
