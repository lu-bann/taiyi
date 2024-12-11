use std::{fmt::Debug, net::SocketAddr, time::Instant};

use alloy_consensus::{BlockHeader, Transaction, TxEnvelope};
use alloy_eips::{eip2718::Decodable2718, BlockId};
use alloy_network::{Ethereum, TransactionBuilder};
use alloy_primitives::{hex, U256};
use alloy_provider::{ext::DebugApi, Provider, ProviderBuilder};
use alloy_rpc_types::{BlockTransactionsKind, TransactionRequest};
use alloy_rpc_types_trace::geth::{
    CallFrame, GethDebugBuiltInTracerType, GethDebugTracingCallOptions, GethDebugTracingOptions,
    GethTrace,
};
use alloy_transport::Transport;
use axum::{
    extract::{Path, State},
    response::{IntoResponse, Json},
    routing::{delete, get, post},
    Router,
};
use eyre::OptionExt;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use taiyi_primitives::{
    CancelPreconfRequest, CancelPreconfResponse, EstimateFeeRequest, EstimateFeeResponse,
    PreconfHash, PreconfRequest, PreconfResponse, PreconfStatusResponse, PreconfTxRequest,
};
use tokio::net::TcpListener;
use tracing::{error, info};
use uuid::Uuid;

use super::state::GetSlotResponse;
use crate::{
    error::RpcError,
    metrics::preconfer::{
        PRECONF_CANCEL_RECEIVED, PRECONF_REQUEST_RECEIVED, PRECONF_RESPONSE_DURATION,
        PRECONF_TX_RECEIVED,
    },
    preconf_api::PreconfState,
};

pub const PRECONF_REQUEST_PATH: &str = "/commitments/v1/preconf_request";
pub const PRECONF_REQUEST_TX_PATH: &str = "/commitments/v1/preconf_request/tx";
pub const PRECONF_REQUEST_STATUS_PATH: &str = "/commitments/v1/preconf_request/:preconf_hash";
pub const AVAILABLE_SLOT_PATH: &str = "/commitments/v1/slots";
pub const ESTIMATE_TIP_PATH: &str = "/gateway/v0/estimate_fee";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetPreconfRequestQuery {
    preconf_hash: PreconfHash,
}

pub struct PreconfApiServer {
    /// The address to bind the server to
    addr: SocketAddr,
}

impl PreconfApiServer {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub async fn run(self, state: PreconfState) -> eyre::Result<()> {
        let app = Router::new()
            .route(PRECONF_REQUEST_PATH, post(handle_preconf_request))
            .route(PRECONF_REQUEST_PATH, delete(delete_preconf_request))
            .route(PRECONF_REQUEST_TX_PATH, post(handle_preconf_request_tx))
            .route(PRECONF_REQUEST_STATUS_PATH, get(get_preconf_request))
            .route(AVAILABLE_SLOT_PATH, get(get_slots))
            .route("/health", get(health_check))
            .route(ESTIMATE_TIP_PATH, post(handle_estimate_tip))
            .with_state(state);

        info!("Starting rpc server...");
        let listener = match TcpListener::bind(&self.addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Failed to bind to {}: {:?}", self.addr, e);
                return Err(e.into());
            }
        };

        tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app).await {
                error!(?err, "preconf API Server error");
            }
        });

        info!("Started rpc server on http://{} ", self.addr);
        Ok(())
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }
}

// Health check endpoint
pub async fn health_check() -> impl IntoResponse {
    Json(json!({"status": "OK"}))
}

pub async fn handle_preconf_request(
    State(state): State<PreconfState>,
    Json(preconf_request): Json<PreconfRequest>,
) -> Result<Json<PreconfResponse>, RpcError> {
    let start_request = Instant::now();
    match state.request_preconf(preconf_request).await {
        Ok(response) => {
            let request_latency = start_request.elapsed();
            PRECONF_RESPONSE_DURATION
                .with_label_values(&[StatusCode::OK.as_str(), PRECONF_REQUEST_PATH])
                .observe(request_latency.as_secs_f64());
            PRECONF_REQUEST_RECEIVED
                .with_label_values(&[StatusCode::OK.as_str(), PRECONF_REQUEST_PATH])
                .inc();
            Ok(Json(response))
        }
        Err(e) => {
            let request_latency = start_request.elapsed();
            PRECONF_RESPONSE_DURATION
                .with_label_values(&[StatusCode::OK.as_str(), PRECONF_REQUEST_PATH])
                .observe(request_latency.as_secs_f64());
            PRECONF_REQUEST_RECEIVED
                .with_label_values(&[StatusCode::BAD_REQUEST.as_str(), PRECONF_REQUEST_PATH])
                .inc();
            Err(e)
        }
    }
}

pub async fn delete_preconf_request(
    State(state): State<PreconfState>,
    Json(cancel_request): Json<CancelPreconfRequest>,
) -> Result<Json<CancelPreconfResponse>, RpcError> {
    match state.cancel_preconf_request(cancel_request).await {
        Ok(response) => {
            PRECONF_CANCEL_RECEIVED
                .with_label_values(&[StatusCode::OK.as_str(), PRECONF_REQUEST_PATH])
                .inc();
            Ok(Json(response))
        }
        Err(e) => {
            PRECONF_CANCEL_RECEIVED
                .with_label_values(&[StatusCode::BAD_REQUEST.as_str(), PRECONF_REQUEST_PATH])
                .inc();
            Err(e.into())
        }
    }
}

pub async fn handle_preconf_request_tx(
    State(state): State<PreconfState>,
    Json(request): Json<PreconfTxRequest>,
) -> Result<impl IntoResponse, RpcError> {
    let start_request = Instant::now();
    match state.preconf_transaction(request.request_id, request.transaction).await {
        Ok(response) => {
            let request_latency = start_request.elapsed();
            PRECONF_RESPONSE_DURATION
                .with_label_values(&[StatusCode::OK.as_str(), PRECONF_REQUEST_TX_PATH])
                .observe(request_latency.as_secs_f64());
            PRECONF_TX_RECEIVED
                .with_label_values(&[StatusCode::OK.as_str(), PRECONF_REQUEST_TX_PATH])
                .inc();
            Ok(Json(response))
        }
        Err(e) => {
            let request_latency = start_request.elapsed();
            PRECONF_RESPONSE_DURATION
                .with_label_values(&[StatusCode::OK.as_str(), PRECONF_REQUEST_TX_PATH])
                .observe(request_latency.as_secs_f64());
            PRECONF_TX_RECEIVED
                .with_label_values(&[StatusCode::BAD_REQUEST.as_str(), PRECONF_REQUEST_TX_PATH])
                .inc();
            Err(e)
        }
    }
}

pub async fn get_preconf_request(
    State(state): State<PreconfState>,
    Path(params): Path<Uuid>,
) -> Result<Json<PreconfStatusResponse>, RpcError> {
    Ok(Json(state.check_preconf_request_status(params).await?))
}

/// Returns the slots for which there is a opted in validator for current epoch and next epoch
pub async fn get_slots(
    State(state): State<PreconfState>,
) -> Result<Json<Vec<GetSlotResponse>>, RpcError> {
    Ok(Json(state.get_slots().await?))
}

pub async fn handle_estimate_tip(
    State(state): State<PreconfState>,
    Json(_request): Json<EstimateFeeRequest>,
) -> Result<Json<EstimateFeeResponse>, RpcError> {
    let client = state.execution_api_client().map_err(|e| RpcError::UnknownError(e.to_string()))?;
    let rpc_client = state.rpc_client().map_err(|e| RpcError::UnknownError(e.to_string()))?;
    let block_number =
        client.get_block_number().await.map_err(|e| RpcError::UnknownError(e.to_string()))?;
    let mut batch = rpc_client.new_batch();
    let mut handlers = Vec::new();
    #[derive(Debug, Serialize, Deserialize, Clone)]
    #[serde(rename_all = "camelCase")]
    struct BlockResp {
        pub base_fee_per_gas: String,
    }
    for n in (block_number - 10)..block_number {
        let call = batch
            .add_call("eth_getBlockByNumber", &(format!("0x{n:x}"), false))
            .map_err(|e| RpcError::UnknownError(e.to_string()))?
            .map_resp(|resp: BlockResp| {
                let hex_str = resp.base_fee_per_gas.trim_start_matches("0x");
                u64::from_str_radix(hex_str, 16).expect("Failed to parse base fee")
            });
        handlers.push(call);
    }
    batch.send().await.map_err(|e| RpcError::UnknownError(e.to_string()))?;
    let results = futures::future::join_all(handlers).await;
    let mut sum = 0;
    let len = results.len();
    for r in results {
        sum += r.map_err(|e| RpcError::UnknownError(e.to_string()))?;
    }
    let fee = sum / len as u64;
    Ok(Json(EstimateFeeResponse { fee }))
}
