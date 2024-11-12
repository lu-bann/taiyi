use std::{fmt::Debug, net::SocketAddr, time::Instant};

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Json},
    routing::{delete, get, post},
    Router,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use taiyi_primitives::{
    AvailableSlotResponse, CancelPreconfRequest, CancelPreconfResponse, PreconfHash,
    PreconfRequest, PreconfResponse, PreconfStatusResponse, PreconfTxRequest,
};
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::{
    error::RpcError,
    metrics::preconfer::{
        PRECONF_CANCEL_RECEIVED, PRECONF_REQUEST_RECEIVED, PRECONF_RESPONSE_DURATION,
        PRECONF_TX_RECEIVED,
    },
    preconf_api::PreconfState,
};

const PRECONF_REQUEST_PATH: &str = "/commitments/v1/preconf_request";
const PRECONF_REQUEST_TX_PATH: &str = "/commitments/v1/preconf_request/tx";
const PRECONF_REQUEST_STATUS_PATH: &str = "/commitments/v1/preconf_request/:preconf_hash";
const AVAILABLE_SLOT_PATH: &str = "/commitments/v1/slots";

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

    pub async fn run(self, state: PreconfState) -> eyre::Result<()>
where {
        let app = Router::new()
            .route(PRECONF_REQUEST_PATH, post(handle_preconf_request))
            .route(PRECONF_REQUEST_PATH, delete(delete_preconf_request))
            .route(PRECONF_REQUEST_TX_PATH, post(handle_preconf_request_tx))
            .route(PRECONF_REQUEST_STATUS_PATH, get(get_preconf_request))
            .route(AVAILABLE_SLOT_PATH, get(get_slots))
            .route("/health", get(health_check))
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
    match state.send_preconf_request(preconf_request).await {
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
    match state.send_preconf_tx_request(request.preconf_hash, request.tx).await {
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
    Path(params): Path<GetPreconfRequestQuery>,
) -> Result<Json<PreconfStatusResponse>, RpcError> {
    Ok(Json(state.check_preconf_request_status(params.preconf_hash).await?))
}

pub async fn get_slots(
    State(state): State<PreconfState>,
) -> Result<Json<AvailableSlotResponse>, RpcError> {
    Ok(Json(state.available_slot().await?))
}
