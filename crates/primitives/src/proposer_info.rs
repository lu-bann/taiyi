use std::ops::Deref;

use alloy_rpc_types_beacon::BlsPublicKey;
use beacon_api_client::ProposerDuty;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProposerInfo {
    pub pubkey: BlsPublicKey,
    pub validator_index: u64,
    pub slot: u64,
}

impl From<ProposerDuty> for ProposerInfo {
    fn from(value: ProposerDuty) -> Self {
        ProposerInfo {
            pubkey: BlsPublicKey::try_from(value.public_key.deref().as_ref())
                .expect("Invalid public key"),
            validator_index: value.validator_index as u64,
            slot: value.slot,
        }
    }
}
