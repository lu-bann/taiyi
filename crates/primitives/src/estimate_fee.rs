use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PreconfFeeResponse {
    pub gas_fee: u128,
    pub blob_gas_fee: u128,
}
