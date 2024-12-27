use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct EstimateFeeRequest {
    pub slot: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct EstimateFeeResponse {
    pub fee: u128,
}
