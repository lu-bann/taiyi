use alloy_core::primitives::Bytes;
use serde::{Deserialize, Serialize};

use super::PreconfHash;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CancelPreconfRequest {
    pub preconf_hash: PreconfHash,
    signature: Bytes,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CancelPreconfResponse {}
