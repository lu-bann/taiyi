#![allow(dead_code)]
use alloy_contract::Error as AlloyContractError;
use axum::{
    response::{IntoResponse, Response},
    Json,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use taiyi_primitives::PreconfHash;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("preconf tx already set")]
    PreconfTxAlreadySet(PreconfHash),
    #[error("Expected target slot {0}, got {1}")]
    SlotMismatch(u64, u64),
    #[error("unknown error {0:?}")]
    UnknownError(String),
    #[error("contract error: {0:?}")]
    ContractError(#[from] AlloyContractError),
    #[error("Orderpool error: {0:?}")]
    OrderPoolError(#[from] PoolError),
    #[error("Proposer error: {0:?}")]
    ProposerError(#[from] ProposerError),
    #[error("Validation error: {0:?}")]
    ValidationError(#[from] ValidationError),
    #[error("Taiyi pricer error: {0:?}")]
    PricerError(#[from] PricerError),
    #[error("Escrow Error: {0:?}")]
    EscrowError(String),
    #[error("Preconf request error: {0:?}")]
    PreconfRequestError(String),
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
    /// The transaction nonce is too low.
    #[error("Transaction nonce too low. Expected {0}, got {1}")]
    NonceTooLow(u64, u64),
    /// The transaction nonce is too high.
    #[error("Transaction nonce too high")]
    NonceTooHigh(u64, u64),
    /// The gas limit is too high.
    #[error("Gas limit too high")]
    GasLimitTooHigh,
    /// TODO: Re-enable chainId check https://github.com/lu-bann/taiyi/issues/111s
    /// The transaction chain ID does not match the expected chain ID.
    // #[error("Chain ID mismatch")]
    // ChainIdMismatch,
    /// NOTE: this should not be exposed to the user.
    #[error("Internal error: {0}")]
    Internal(String),
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

#[derive(Debug, Error)]
pub enum PoolError {
    #[error("Order pool is empty")]
    OrderPoolIsEmpty,
    #[error("Prioritized Orderpool not initialized")]
    PrioritizedOrderPoolNotInitialized,
    #[error("Max commitments reached for slot {0}: {1}")]
    MaxCommitmentsReachedForSlot(u64, usize),
    #[error("Preconf request slot {0} is too old, current slot is {1}")]
    PreconfRequestSlotTooOld(u64, u64),
    #[error("Max gas limit reached for slot {0}: {1}")]
    MaxGasLimitReachedForSlot(u64, u64),
    #[error("preconf request {0:?} not found")]
    PreconfRequestNotFound(PreconfHash),
    #[error("preconf request {0:?} already exists")]
    PreconfRequestAlreadyExist(PreconfHash),
    #[error("slot {0} not ready")]
    SlotNotReady(u64),
    #[error("unknown error {0:?}")]
    UnknownError(String),
}
