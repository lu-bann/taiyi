use alloy::contract::Error as AlloyContractError;
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
