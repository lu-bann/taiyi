use alloy_primitives::{Address, B256, U256};
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

    pub fn digest(&self, chain_id: u64) -> B256 {
        match self {
            PreconfRequest::TypeA(req) => req.digest(chain_id),
            PreconfRequest::TypeB(req) => req.digest(chain_id),
        }
    }

    pub fn sequence_num(&self) -> Option<u64> {
        match self {
            PreconfRequest::TypeA(req) => req.sequence_number,
            PreconfRequest::TypeB(_) => panic!("Type B does not have sequence number"),
        }
    }

    /// Amount to be paid to the underwriter
    pub fn preconf_tip(&self) -> U256 {
        match self {
            PreconfRequest::TypeA(req) => req.preconf_tip(),
            PreconfRequest::TypeB(req) => req.preconf_tip(),
        }
    }

    pub fn signer(&self) -> Address {
        match self {
            PreconfRequest::TypeA(req) => req.signer(),
            PreconfRequest::TypeB(req) => req.signer(),
        }
    }
}
