use alloy_consensus::TxEnvelope;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PreconfTxRequest {
    pub request_id: Uuid,
    pub transaction: TxEnvelope,
}
