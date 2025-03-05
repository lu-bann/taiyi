use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

use crate::{PreconfRequestTypeA, PreconfRequestTypeB};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum PreconfRequest {
    TypeA(PreconfRequestTypeA),
    TypeB(PreconfRequestTypeB),
}

impl PreconfRequest {
    pub fn target_slot(&self) -> u64 {
        match self {
            PreconfRequest::TypeA(req) => req.target_slot(),
            PreconfRequest::TypeB(req) => req.target_slot(),
        }
    }

    pub fn digest(&self) -> B256 {
        match self {
            PreconfRequest::TypeA(req) => req.digest(),
            PreconfRequest::TypeB(req) => req.digest(),
        }
    }
}
