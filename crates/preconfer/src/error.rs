use alloy::contract::Error as AlloyContractError;
use jsonrpsee::types::ErrorObjectOwned;
use luban_primitives::PreconfHash;
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

impl From<RpcError> for ErrorObjectOwned {
    fn from(err: RpcError) -> Self {
        match err {
            RpcError::PreconfRequestNotFound(_) => {
                ErrorObjectOwned::owned(404, format!("{err:?}"), None::<bool>)
            }
            RpcError::PreconfRequestAlreadyExist(_) => {
                ErrorObjectOwned::owned(400, format!("{err:?}"), None::<bool>)
            }
            RpcError::PreconfTxAlreadySet(_) => {
                ErrorObjectOwned::owned(400, format!("{err:?}"), None::<bool>)
            }
            RpcError::PreconfTxNotValid(_) => {
                ErrorObjectOwned::owned(400, format!("{err:?}"), None::<bool>)
            }
            RpcError::UnknownError(_) => {
                ErrorObjectOwned::owned(500, format!("{err:?}"), None::<bool>)
            }
            RpcError::ContractError(_) => {
                ErrorObjectOwned::owned(500, format!("{err:?}"), None::<bool>)
            }
        }
    }
}
