use std::{net::SocketAddr, str::FromStr};

use alloy_primitives::PrimitiveSignature;
use alloy_provider::Provider;
use axum::{
    extract::State,
    middleware,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use reqwest::header::HeaderMap;
use serde_json::json;
use taiyi_primitives::{
    BlockspaceAllocation, PreconfFeeResponse, PreconfResponse, SlotInfo, SubmitTransactionRequest,
    SubmitTypeATransactionRequest,
};
use tokio::net::TcpListener;
use tracing::{error, info};
use uuid::Uuid;

use crate::{error::RpcError, metrics::metrics_middleware, preconf_api::PreconfState};

pub const AVAILABLE_SLOT_PATH: &str = "/commitments/v0/slots";
pub const PRECONF_FEE_PATH: &str = "/commitments/v0/preconf_fee";
pub const RESERVE_BLOCKSPACE_PATH: &str = "/commitments/v0/reserve_blockspace";
pub const SUBMIT_TYPEA_TRANSACTION_PATH: &str = "/commitments/v0/submit_tx_type_a";
pub const SUBMIT_TRANSACTION_PATH: &str = "/commitments/v0/submit_tx_type_b";

pub struct PreconfApiServer {
    /// The address to bind the server to
    addr: SocketAddr,
}

impl PreconfApiServer {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub async fn run<P>(self, state: PreconfState<P>) -> eyre::Result<()>
    where
        P: Provider + Clone + Send + Sync + 'static,
    {
        let app = Router::new()
            .route(RESERVE_BLOCKSPACE_PATH, post(handle_reserve_blockspace))
            .route(SUBMIT_TRANSACTION_PATH, post(handle_submit_transaction))
            .route(SUBMIT_TYPEA_TRANSACTION_PATH, post(handle_submit_typea_transaction))
            .route(AVAILABLE_SLOT_PATH, get(get_slots))
            .route("/health", get(health_check))
            .route(PRECONF_FEE_PATH, post(handle_preconf_fee))
            .layer(middleware::from_fn(metrics_middleware))
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

    #[allow(dead_code)]
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }
}

// Health check endpoint
pub async fn health_check() -> impl IntoResponse {
    Json(json!({"status": "OK"}))
}

pub async fn handle_reserve_blockspace<P>(
    headers: HeaderMap,
    State(state): State<PreconfState<P>>,
    Json(request): Json<BlockspaceAllocation>,
) -> Result<Json<Uuid>, RpcError>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    let signature = {
        let auth = headers
            .get("x-luban-signature")
            .ok_or(RpcError::UnknownError("no signature".to_string()))?;

        let sig = auth.to_str().map_err(|_| RpcError::MalformedHeader)?;
        PrimitiveSignature::from_str(sig).expect("Failed to parse signature")
    };

    let signer = signature
        .recover_address_from_prehash(&request.digest())
        .map_err(|e| RpcError::SignatureError(e.to_string()))?;

    info!("Received blockspace reservation request, signer: {}", signer);

    match state.reserve_blockspace(request, signature, signer).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => Err(e),
    }
}

pub async fn handle_submit_transaction<P>(
    headers: HeaderMap,
    State(state): State<PreconfState<P>>,
    Json(request): Json<SubmitTransactionRequest>,
) -> Result<Json<PreconfResponse>, RpcError>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    let signature = {
        let auth = headers
            .get("x-luban-signature")
            .ok_or(RpcError::UnknownError("no signature".to_string()))?;

        let sig = auth.to_str().map_err(|_| RpcError::MalformedHeader)?;
        PrimitiveSignature::from_str(sig).expect("Failed to parse signature")
    };

    match state.submit_transaction(request, signature).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => Err(e),
    }
}

/// Returns the slots for which there is a opted in validator for current epoch and next epoch
pub async fn get_slots<P>(
    State(state): State<PreconfState<P>>,
) -> Result<Json<Vec<SlotInfo>>, RpcError>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    Ok(Json(state.get_slots().await?))
}

pub async fn handle_preconf_fee<P>(
    State(_): State<PreconfState<P>>,
    Json(_request): Json<u64>,
) -> Result<Json<PreconfFeeResponse>, RpcError>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    Ok(Json(PreconfFeeResponse { gas_fee: 1, blob_gas_fee: 1 }))
}

pub async fn handle_submit_typea_transaction<P>(
    headers: HeaderMap,
    State(state): State<PreconfState<P>>,
    Json(request): Json<SubmitTypeATransactionRequest>,
) -> Result<Json<PreconfResponse>, RpcError>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    let signature = {
        let auth = headers
            .get("x-luban-signature")
            .ok_or(RpcError::UnknownError("no signature".to_string()))?;

        let sig = auth.to_str().map_err(|_| RpcError::MalformedHeader)?;
        PrimitiveSignature::from_str(sig).expect("Failed to parse signature")
    };

    let signer = signature
        .recover_address_from_prehash(&request.digest())
        .map_err(|e| RpcError::SignatureError(e.to_string()))?;

    match state.submit_typea_transaction(request, signature, signer).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => Err(e),
    }
}
