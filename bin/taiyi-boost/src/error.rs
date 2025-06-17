// the code is modified from bolt's implementation: https://github.com/chainbound/bolt/blob/eed9cec9b644632550479f05823b4487d3ed1ed6/bolt-sidecar/src/builder/mod.rs#L46
use alloy_rpc_types_engine::{ClientCode, PayloadStatusEnum};
use taiyi_beacon_client::BeaconClientError;

#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("{0}")]
    BeaconClient(#[from] BeaconClientError),
    #[error("Failed to parse from integer: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("Failed to de/serialize JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Failed to decode hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Invalid JWT: {0}")]
    Jwt(#[from] alloy_rpc_types_engine::JwtError),
    #[error("Failed HTTP request: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Failed while fetching from RPC: {0}")]
    Transport(#[from] alloy_transport::TransportError),
    #[error("Failed to build payload due to invalid transactions: {0}")]
    InvalidTransactions(String),
    #[error("Got an unexpected response from engine_newPayload query: {0}")]
    UnexpectedPayloadStatus(PayloadStatusEnum),
    #[error("Failed to parse any hints from engine API; el_name: {0}, validation error: {1}")]
    FailedToParseHintsFromEngine(String, String),
    #[error("Unsupported engine hint: {0}")]
    UnsupportedEngineHint(String),
    #[error("Unsupported engine client: {0}")]
    UnsupportedEngineClient(ClientCode),
    #[error("Failed to gather hints after {0} iterations")]
    ExceededMaxHintIterations(u64),
    #[error("Failed to parse client info from Engine response")]
    MissingClientInfo,
}
