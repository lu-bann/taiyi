use reth_primitives::PooledTransactionsElement;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PreconfTxRequest {
    pub request_id: Uuid,
    pub transaction: PooledTransactionsElement,
}
