use alloy_consensus::TxEnvelope;
use serde::{Deserialize, Serialize};

use crate::PreconfHash;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PreconfTxRequest {
    pub preconf_hash: PreconfHash,
    pub tx: TxEnvelope,
}
