use std::{fmt::Debug, net::SocketAddr, str::FromStr, time::Instant};

use alloy_network::Ethereum;
use alloy_primitives::{Address, Signature};
use alloy_provider::Provider;
use alloy_transport::Transport;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
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
const PRECONF_REQUEST_PATH: &str = "/commitments/v1/preconf_request";
const PRECONF_REQUEST_TX_PATH: &str = "/commitments/v1/preconf_request/tx";
const PRECONF_REQUEST_STATUS_PATH: &str = "/commitments/v1/preconf_request/:preconf_hash";
const AVAILABLE_SLOT_PATH: &str = "/commitments/v1/slots";

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

    pub async fn run<T, P>(self, state: PreconfState<T, P>) -> eyre::Result<()>
    where
        T: Transport + Clone + Send + Sync + 'static,
        P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
    {
        let app = Router::new()
            .route(INCLUSION_REQUEST_PATH, post(inlusion_request))
            // .route(PRECONF_REQUEST_PATH, post(handle_preconf_request))
            // .route(PRECONF_REQUEST_PATH, delete(delete_preconf_request))
            // .route(PRECONF_REQUEST_TX_PATH, post(handle_preconf_request_tx))
            // .route(PRECONF_REQUEST_STATUS_PATH, get(get_preconf_request))
            // .route(AVAILABLE_SLOT_PATH, get(get_slots))
            .with_state(state);

        info!("Starting rpc server on http://{}:{} ", self.addr.ip(), self.addr.port());
        let listener = match TcpListener::bind(&self.addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Failed to bind to {}: {:?}", self.addr, e);
                return Err(e.into());
            }
        };
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("Server error: {e:?}");
            return Err(e.into());
        }
        Ok(())
    }
}

pub async fn inlusion_request<T, P>(
    headers: HeaderMap,
    State(state): State<PreconfState<T, P>>,
    Json(payload): Json<JsonPayload>,
) -> Result<Json<JsonResponse>, RpcError>
where
    T: Transport + Clone + Send + Sync + 'static,
    P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
{
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

// pub async fn handle_preconf_request<T, P, F>(
//     State(state): State<PreconfState<T, P, F>>,
//     Json(preconf_request): Json<PreconfRequest>,
// ) -> Result<Json<PreconfResponse>, RpcError>
// where
//     T: Transport + Clone + Send + Sync + 'static,
//     P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
//     F: PreconfPricer + Clone + Send + Sync + 'static,
// {
//     let start_request = Instant::now();
//     match state.send_preconf_request(preconf_request).await {
//         Ok(response) => {
//             let request_latency = start_request.elapsed();
//             PRECONF_RESPONSE_DURATION
//                 .with_label_values(&[StatusCode::OK.as_str(), PRECONF_REQUEST_PATH])
//                 .observe(request_latency.as_secs_f64());
//             PRECONF_REQUEST_RECEIVED
//                 .with_label_values(&[StatusCode::OK.as_str(), PRECONF_REQUEST_PATH])
//                 .inc();
//             Ok(Json(response))
//         }
//         Err(e) => {
//             let request_latency = start_request.elapsed();
//             PRECONF_RESPONSE_DURATION
//                 .with_label_values(&[StatusCode::OK.as_str(), PRECONF_REQUEST_PATH])
//                 .observe(request_latency.as_secs_f64());
//             PRECONF_REQUEST_RECEIVED
//                 .with_label_values(&[StatusCode::BAD_REQUEST.as_str(), PRECONF_REQUEST_PATH])
//                 .inc();
//             Err(e)
//         }
//     }
// }

// pub async fn delete_preconf_request<T, P, F>(
//     State(state): State<PreconfState<T, P, F>>,
//     Json(cancel_request): Json<CancelPreconfRequest>,
// ) -> Result<Json<CancelPreconfResponse>, RpcError>
// where
//     T: Transport + Clone + Send + Sync + 'static,
//     P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
//     F: PreconfPricer + Clone + Send + Sync + 'static,
// {
//     match state.cancel_preconf_request(cancel_request).await {
//         Ok(response) => {
//             PRECONF_CANCEL_RECEIVED
//                 .with_label_values(&[StatusCode::OK.as_str(), PRECONF_REQUEST_PATH])
//                 .inc();
//             Ok(Json(response))
//         }
//         Err(e) => {
//             PRECONF_CANCEL_RECEIVED
//                 .with_label_values(&[StatusCode::BAD_REQUEST.as_str(), PRECONF_REQUEST_PATH])
//                 .inc();
//             Err(e.into())
//         }
//     }
// }

// pub async fn handle_preconf_request_tx<T, P, F>(
//     State(state): State<PreconfState<T, P, F>>,
//     Json(request): Json<PreconfTxRequest>,
// ) -> Result<impl IntoResponse, RpcError>
// where
//     T: Transport + Clone + Send + Sync + 'static,
//     P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
//     F: PreconfPricer + Clone + Send + Sync + 'static,
// {
//     let start_request = Instant::now();
//     match state.send_preconf_tx_request(request.preconf_hash, request.tx).await {
//         Ok(response) => {
//             let request_latency = start_request.elapsed();
//             PRECONF_RESPONSE_DURATION
//                 .with_label_values(&[StatusCode::OK.as_str(), PRECONF_REQUEST_TX_PATH])
//                 .observe(request_latency.as_secs_f64());
//             PRECONF_TX_RECEIVED
//                 .with_label_values(&[StatusCode::OK.as_str(), PRECONF_REQUEST_TX_PATH])
//                 .inc();
//             Ok(Json(response))
//         }
//         Err(e) => {
//             let request_latency = start_request.elapsed();
//             PRECONF_RESPONSE_DURATION
//                 .with_label_values(&[StatusCode::OK.as_str(), PRECONF_REQUEST_TX_PATH])
//                 .observe(request_latency.as_secs_f64());
//             PRECONF_TX_RECEIVED
//                 .with_label_values(&[StatusCode::BAD_REQUEST.as_str(), PRECONF_REQUEST_TX_PATH])
//                 .inc();
//             Err(e)
//         }
//     }
// }

// pub async fn get_preconf_request<T, P, F>(
//     State(state): State<PreconfState<T, P, F>>,
//     Path(params): Path<GetPreconfRequestQuery>,
// ) -> Result<Json<PreconfStatusResponse>, RpcError>
// where
//     T: Transport + Clone + Send + Sync + 'static,
//     P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
//     F: PreconfPricer + Clone + Send + Sync + 'static,
// {
//     Ok(Json(state.check_preconf_request_status(params.preconf_hash).await?))
// }

// pub async fn get_slots<T, P, F>(
//     State(state): State<PreconfState<T, P, F>>,
// ) -> Result<Json<AvailableSlotResponse>, RpcError>
// where
//     T: Transport + Clone + Send + Sync + 'static,
//     P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
//     F: PreconfPricer + Clone + Send + Sync + 'static,
// {
//     Ok(Json(state.available_slot().await?))
// }
