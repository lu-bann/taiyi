use alloy_primitives::Signature;
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
    pub commitment: Option<Signature>,
}

impl PreconfResponse {
    pub fn success(request_id: Uuid, commitment: Option<Signature>) -> Self {
        Self {
            status: "success".to_string(),
            message:
                "Your preconf request has been successfully received and is pending processing."
                    .to_string(),
            data: PreconfResponseData { request_id, commitment },
        }
    }
}
