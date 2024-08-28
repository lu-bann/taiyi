use alloy_contract::Error as AlloyContractError;
use axum::{
    response::{IntoResponse, Response},
    Json,
};
use luban_primitives::PreconfHash;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("preconf request {0:?} not found")]
    PreconfRequestNotFound(PreconfHash),
    #[error("preconf request {0:?} already exists")]
    PreconfRequestAlreadyExist(PreconfHash),
    #[error("preconf tx already set")]
    PreconfTxAlreadySet(PreconfHash),
    #[error("invalid preconf tx: {0:?}")]
    PreconfTxNotValid(String),
    #[error("unknown error {0:?}")]
    UnknownError(String),
    #[error("contract error: {0:?}")]
    ContractError(#[from] AlloyContractError),
    #[error("Max commitments reached for slot {0}: {1}")]
    MaxCommitmentsReachedForSlot(u64, usize),
    #[error("Preconf request slot {0} is too old, current slot is {1}")]
    PreconfRequestSlotTooOld(u64, u64),
    #[error("Max gas limit reached for slot {0}: {1}")]
    MaxGasLimitReachedForSlot(u64, u64),
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
        (
            code,
            Json(ErrorMessage {
                code: code.as_u16(),
                message,
            }),
        )
            .into_response()
    }
}
