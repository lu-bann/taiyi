use alloy_rpc_types_beacon::BlsSignature;
use serde::{Deserialize, Serialize};

use crate::PreconfHash;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PreconfResponse {
    status: String,
    message: String,
    data: PreconfResponseData,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PreconfResponseData {
    preconf_hash: PreconfHash,
    preconfer_signature: BlsSignature,
}

impl PreconfResponse {
    pub fn success(preconf_hash: PreconfHash, preconfer_signature: BlsSignature) -> Self {
        Self {
            status: "success".to_string(),
            message:
                "Your preconf request has been successfully received and is pending processing."
                    .to_string(),
            data: PreconfResponseData {
                preconf_hash,
                preconfer_signature,
            },
        }
    }
}
