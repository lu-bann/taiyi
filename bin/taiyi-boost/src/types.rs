use std::fmt::Debug;

use alloy::rpc::types::beacon::{BlsPublicKey, BlsSignature};
use serde::{Deserialize, Serialize};
use tree_hash_derive::TreeHash;

pub const ELECT_PRECONFER_PATH: &str = "/eth/v1/builder/elect_preconfer";

#[derive(Debug, Clone, Deserialize)]
pub struct ExtraConfig {
    pub trusted_preconfer: BlsPublicKey,
    pub beacon_node: String,
    pub chain_id: u64,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, TreeHash)]
pub struct ElectPreconferRequest {
    pub preconfer_pubkey: BlsPublicKey,
    pub slot_number: u64,
    pub chain_id: u64,
    pub gas_limit: u64,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize)]
pub struct SignedRequest<T>
where
    T: Debug + Default + Clone + Eq + PartialEq + Serialize,
{
    pub message: T,
    pub signature: BlsSignature,
}
