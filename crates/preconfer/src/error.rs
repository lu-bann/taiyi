#![allow(dead_code)]
use alloy_consensus::BlobTransactionValidationError;
use alloy_primitives::{Address, U256};
use axum::{
    response::{IntoResponse, Response},
    Json,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
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
    #[error("Preconf pool error: {0:?}")]
    PoolError(#[from] PoolError),
    #[error("Preconf request error: {0:?}")]
    PreconfRequestError(String),
    #[error("Signature error: {0:?}")]
    SignatureError(String),
    #[error("Params error: {0:?}")]
    ParamsError(String),
    #[error("Malformed header")]
    MalformedHeader,
    #[error("Gateway isn't delegated for the slot: {0}")]
    SlotNotAvailable(u64),
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
#[derive(Debug, Error)]
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
    LowBalance(U256),
    #[error("Failed to get account state for address: {0}")]
    AccountStateNotFound(Address),
    #[error("Signer not found for preconf request")]
    SignerNotFound,
    #[error("Transaction not found for preconf request")]
    TransactionNotFound,
    #[error("custom error {0:?}")]
    CustomError(String),
    #[error("Invalid blob {0:?}")]
    BlobValidation(#[from] BlobTransactionValidationError),
    #[error("Blob count exceeds limit, expected not more than {0}, got {1}")]
    BlobCountExceedsLimit(usize, usize),
    #[error("Tip tarnsaction must be a valid ETH transfer")]
    InvalidTipTransaction,
    #[error("Nonce not continuous, tip_tx_nonce: {0}, preconf_tx_nonce: {1}")]
    InvalidNonceSequence(u64, u64),
}

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

#[derive(Debug, Error)]
pub enum PoolError {
    /// Request validation failed.
    #[error("Validation failed: {0}")]
    Validation(#[from] ValidationError),
    #[error("Target slot: {0}, current slot: {1}")]
    TargetSlotInPast(u64, u64),
    #[error("preconf request {0:?} not found")]
    PreconfRequestNotFound(Uuid),
    #[error("preconf request for slot {0} not found")]
    RequestsNotFoundForSlot(u64),
    #[error("Invalid preconf tx for hash: {0:?}")]
    InvalidPreconfTx(Uuid),
    #[error("requested gas limit {0} exceeds max available gas limit {1}")]
    InsufficientGasLimit(u64, u64),
    #[error("requested blobs {0} exceeds max available blobs {1}")]
    InsufficientBlobs(usize, usize),
    #[error("Insufficient escrow balance, present: {0}, required: {1}")]
    InsufficientEscrowBalance(U256, U256),
    #[error("Blockspace not available")]
    BlockspaceNotAvailable,
    #[error("Transaction not found")]
    TransactionNotFound,
    #[error("Escrow balance not found for account {0}")]
    EscrowBalanceNotFoundForAccount(Address),
}
