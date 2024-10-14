use std::{fmt::Debug, net::SocketAddr};

use alloy_network::Ethereum;
use alloy_provider::Provider;
use alloy_transport::Transport;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use taiyi_primitives::{
    AvailableSlotResponse, CancelPreconfRequest, CancelPreconfResponse, PreconfHash,
    PreconfRequest, PreconfResponse, PreconfStatusResponse, PreconfTxRequest,
};
use tokio::net::TcpListener;

use crate::{error::RpcError, preconf_api::PreconfState, pricer::PreconfPricer};

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

    pub async fn run<T, P, F>(self, state: PreconfState<T, P, F>) -> eyre::Result<()>
    where
        T: Transport + Clone + Send + Sync + 'static,
        P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
        F: PreconfPricer + Clone + Send + Sync + 'static,
    {
        let app = Router::new()
            .route("/commitments/v1/preconf_request", post(handle_preconf_request))
            .route("/commitments/v1/preconf_request", delete(delete_preconf_request))
            .route("/commitments/v1/preconf_request/tx", post(handle_preconf_request_tx))
            .route("/commitments/v1/preconf_request/:preconf_hash", get(get_preconf_request))
            .route("/commitments/v1/slots", get(get_slots))
            .with_state(state);

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

pub async fn handle_preconf_request<T, P, F>(
    State(state): State<PreconfState<T, P, F>>,
    Json(preconf_request): Json<PreconfRequest>,
) -> Result<Json<PreconfResponse>, RpcError>
where
    T: Transport + Clone + Send + Sync + 'static,
    P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
    F: PreconfPricer + Clone + Send + Sync + 'static,
{
    Ok(Json(state.send_preconf_request(preconf_request).await?))
}

pub async fn delete_preconf_request<T, P, F>(
    State(state): State<PreconfState<T, P, F>>,
    Json(cancel_request): Json<CancelPreconfRequest>,
) -> Result<Json<CancelPreconfResponse>, RpcError>
where
    T: Transport + Clone + Send + Sync + 'static,
    P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
    F: PreconfPricer + Clone + Send + Sync + 'static,
{
    Ok(Json(state.cancel_preconf_request(cancel_request).await?))
}

pub async fn handle_preconf_request_tx<T, P, F>(
    State(state): State<PreconfState<T, P, F>>,
    Json(request): Json<PreconfTxRequest>,
) -> Result<impl IntoResponse, RpcError>
where
    T: Transport + Clone + Send + Sync + 'static,
    P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
    F: PreconfPricer + Clone + Send + Sync + 'static,
{
    Ok(Json(state.send_preconf_tx_request(request.preconf_hash, request.tx).await?))
}

pub async fn get_preconf_request<T, P, F>(
    State(state): State<PreconfState<T, P, F>>,
    Path(params): Path<GetPreconfRequestQuery>,
) -> Result<Json<PreconfStatusResponse>, RpcError>
where
    T: Transport + Clone + Send + Sync + 'static,
    P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
    F: PreconfPricer + Clone + Send + Sync + 'static,
{
    Ok(Json(state.check_preconf_request_status(params.preconf_hash).await?))
}

pub async fn get_slots<T, P, F>(
    State(state): State<PreconfState<T, P, F>>,
) -> Result<Json<AvailableSlotResponse>, RpcError>
where
    T: Transport + Clone + Send + Sync + 'static,
    P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
    F: PreconfPricer + Clone + Send + Sync + 'static,
{
    Ok(Json(state.available_slot().await?))
}
