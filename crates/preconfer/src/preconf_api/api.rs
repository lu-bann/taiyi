use std::{fmt::Debug, net::SocketAddr, str::FromStr, time::Instant};

use alloy_network::Ethereum;
use alloy_primitives::{Address, Signature};
use alloy_provider::Provider;
use alloy_transport::Transport;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Json},
    routing::{delete, get, post},
    Router,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use taiyi_primitives::{
    inclusion_request::InclusionRequest, AvailableSlotResponse, CancelPreconfRequest,
    CancelPreconfResponse, PreconfHash, PreconfRequest, PreconfResponse, PreconfStatusResponse,
    PreconfTxRequest,
};
use tokio::net::TcpListener;
use tracing::{error, info};

use super::jsonrpc::{JsonPayload, JsonResponse};
use crate::{
    error::RpcError,
    metrics::preconfer::{
        PRECONF_CANCEL_RECEIVED, PRECONF_REQUEST_RECEIVED, PRECONF_RESPONSE_DURATION,
        PRECONF_TX_RECEIVED,
    },
    preconf_api::PreconfState,
    pricer::PreconfPricer,
};

const INCLUSION_REQUEST_PATH: &str = "/commitments/v1/inclusion_request";
const REQUEST_INCLUSION_METHOD: &str = "luban_requestInclusion";

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
            .route(INCLUSION_REQUEST_PATH, post(inlusion_request))
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

pub async fn inlusion_request(
    headers: HeaderMap,
    State(state): State<PreconfState>,
    Json(payload): Json<JsonPayload>,
) -> Result<Json<JsonResponse>, RpcError> {
    info!("Received new request");

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
        let sig = Signature::from_str(sig).expect("Failed to parse signature");

        (address, sig)
    };

    match payload.method.as_str() {
        REQUEST_INCLUSION_METHOD => {
            let Some(request_json) = payload.params.first().cloned() else {
                return Err(RpcError::UnknownError("Bad params".to_string()));
            };

            // Parse the inclusion request from the parameters
            let mut inclusion_request: InclusionRequest = serde_json::from_value(request_json)
                .map_err(|e| RpcError::UnknownError(e.to_string()))
                .inspect_err(|e| error!("Failed to parse inclusion request: {:?}", e))?;

            info!(?inclusion_request, "New inclusion request");

            // Set the signature here for later processing
            inclusion_request.set_signature(signature);

            // Set the request signer
            inclusion_request.set_signer(signer);

            let inclusion_commitment = state.request_inclusion(inclusion_request).await?;

            // Create the JSON-RPC response
            let response = JsonResponse {
                id: payload.id,
                result: serde_json::to_value(inclusion_commitment)
                    .expect("Failed to serialize response"),
                ..Default::default()
            };

            Ok(Json(response))
        }
        other => {
            error!("Unknown method: {}", other);
            Err(RpcError::UnknownMethod)
        }
    }
}

// Health check endpoint
pub async fn health_check() -> impl IntoResponse {
    Json(json!({"status": "OK"}))
}
