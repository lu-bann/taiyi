#![allow(dead_code)]
use alloy_contract::Error as AlloyContractError;
use alloy_primitives::Address;
use axum::{
    response::{IntoResponse, Response},
    Json,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use taiyi_primitives::PreconfHash;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("preconf tx already set")]
    PreconfTxAlreadySet,
    #[error("unknown error {0:?}")]
    UnknownError(String),
    #[error("exceed deadline for slot {0}")]
    ExceedDeadline(u64),
    #[error("Orderpool error: {0:?}")]
    PoolError(#[from] PoolError),
    #[error("Preconf request error: {0:?}")]
    PreconfRequestError(String),
    #[error("Signature error: {0:?}")]
    SignatureError(String),
    #[error("Params error: {0:?}")]
    ParamsError(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorMessage {
    code: u16,
    message: String,
}

impl IntoResponse for RpcError {
    fn into_response(self) -> Response {
        let message = self.to_string();
        let code = StatusCode::BAD_REQUEST;
        (code, Json(ErrorMessage { code: code.as_u16(), message })).into_response()
    }
}

/// Possible commitment validation errors.
#[derive(Debug, PartialEq, Error)]
pub enum ValidationError {
    #[error("Transaction nonce too low. Expected {0}, got {1}")]
    NonceTooLow(u64, u64),
    #[error("Transaction nonce too high. Expected {0}, got {1}")]
    NonceTooHigh(u64, u64),
    #[error("Gas limit too high")]
    GasLimitTooHigh,
    #[error("Chain ID mismatch")]
    ChainIdMismatch,
    // NOTE: this should not be exposed to the user.
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Insufficient account balance, balance_diff: {0}")]
    LowBalance(u128),
    #[error("Failed to get account state for address: {0}")]
    AccountStateNotFound(Address),
    #[error("custom error {0:?}")]
    CustomError(String),
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum ProposerError {
    #[error("proxy key not found")]
    ProxyKeyNotFound,
    #[error("Proposer duty not found")]
    ProposerDutyNotFound,
}

#[derive(Debug, Error)]
pub enum PricerError {
    #[error("reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("alloy transport error: {0}")]
    TransportError(#[from] alloy_transport::TransportError),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("custom error: {0}")]
    Custom(String),
}

#[derive(Debug, PartialEq, Error)]
pub enum PoolError {
    /// Request validation failed.
    #[error("Validation failed: {0}")]
    Validation(#[from] ValidationError),
    #[error("Target slot: {0}, current slot: {1}")]
    TargetSlotInPast(u64, u64),
    #[error("preconf request {0:?} not found")]
    PreconfRequestNotFound(Uuid),
    #[error("preconf request for slot {0} not found")]
    SlotNotFound(u64),
    #[error("Invalid preconf tx for hash: {0:?}")]
    InvalidPreconfTx(Uuid),
    #[error("requested gas limit {0} exceeds max available gas limit {1}")]
    InsufficientGasLimit(u64, u64),
    #[error("requested blobs {0} exceeds max available blobs {1}")]
    InsufficientBlobs(usize, usize),
}
