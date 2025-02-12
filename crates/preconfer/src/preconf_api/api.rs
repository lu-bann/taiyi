use std::{net::SocketAddr, str::FromStr};

use alloy_primitives::{Address, PrimitiveSignature};
use alloy_provider::Provider;
use axum::{
    extract::{Path, State},
    middleware,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use taiyi_primitives::{
    BlockspaceAllocation, PreconfFeeRequest, PreconfFeeResponse, PreconfHash, PreconfResponse,
    PreconfStatusResponse, SubmitTransactionRequest,
};
use tokio::net::TcpListener;
use tracing::{error, info};
use uuid::Uuid;

use super::state::GetSlotResponse;
use crate::{error::RpcError, metrics::metrics_middleware, preconf_api::PreconfState};

pub const RESERVE_BLOCKSPACE_PATH: &str = "/commitments/v0/reserve_blockspace";
pub const SUBMIT_TRANSACTION_PATH: &str = "/commitments/v0/submit_transaction";
pub const PRECONF_REQUEST_STATUS_PATH: &str = "/commitments/v0/preconf_request/:preconf_hash";
pub const AVAILABLE_SLOT_PATH: &str = "/commitments/v0/slots";
pub const ESTIMATE_TIP_PATH: &str = "/commitments/v0/estimate_fee";

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

    pub async fn run<P>(self, state: PreconfState<P>) -> eyre::Result<()>
    where
        P: Provider + Clone + Send + Sync + 'static,
    {
        let app = Router::new()
            .route(RESERVE_BLOCKSPACE_PATH, post(handle_reserve_blockspace))
            .route(SUBMIT_TRANSACTION_PATH, post(handle_submit_transaction))
            .route(PRECONF_REQUEST_STATUS_PATH, get(get_preconf_request))
            .route(AVAILABLE_SLOT_PATH, get(get_slots))
            .route("/health", get(health_check))
            .route(ESTIMATE_TIP_PATH, post(handle_estimate_tip))
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
    info!("Received blockspace reservation request");

    // Extract the signer and signature from the headers
    let (signer, signature) = {
        let auth = headers
            .get("x-luban-signature")
            .ok_or(RpcError::UnknownError("no signature".to_string()))?;

        // Remove the "0x" prefix
        let auth = auth.to_str().map_err(|_| RpcError::MalformedHeader)?;

        let mut split = auth.split(':');

        let address = split.next().ok_or(RpcError::MalformedHeader)?;
        let address = Address::from_str(address).map_err(|_| RpcError::MalformedHeader)?;

        let sig = split.next().ok_or(RpcError::MalformedHeader)?;
        let sig = PrimitiveSignature::from_str(sig).expect("Failed to parse signature");

        (address, sig)
    };

    // verify the signature
    let recovered_signer = signature
        .recover_address_from_prehash(&request.digest())
        .map_err(|e| RpcError::SignatureError(e.to_string()))?;
    if recovered_signer != signer {
        return Err(RpcError::SignatureError("Invalid signature".to_string()));
    }

    match state.reserve_blockspace(request, signature, signer).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => Err(e),
    }
}

pub async fn handle_submit_transaction<P>(
    headers: HeaderMap,
    State(state): State<PreconfState<P>>,
    Json(param): Json<SubmitTransactionRequest>,
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
    match state.submit_transaction(param, signature).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => Err(e),
    }
}

pub async fn get_preconf_request<P>(
    State(state): State<PreconfState<P>>,
    Path(params): Path<Uuid>,
) -> Result<Json<PreconfStatusResponse>, RpcError>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    Ok(Json(state.check_preconf_request_status(params).await?))
}

/// Returns the slots for which there is a opted in validator for current epoch and next epoch
pub async fn get_slots<P>(
    State(state): State<PreconfState<P>>,
) -> Result<Json<Vec<GetSlotResponse>>, RpcError>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    Ok(Json(state.get_slots().await?))
}

pub async fn handle_estimate_tip<P>(
    State(_): State<PreconfState<P>>,
    Json(_request): Json<PreconfFeeRequest>,
) -> Result<Json<PreconfFeeResponse>, RpcError>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    Ok(Json(PreconfFeeResponse { gas_fee: 1, blob_gas_fee: 1 }))
}
