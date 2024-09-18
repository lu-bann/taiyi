use std::fmt::Debug;

use alloy_network::Ethereum;
use alloy_provider::Provider;
use alloy_transport::Transport;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use cb_pbs::{BuilderApi, PbsState};
use luban_primitives::{
    AvailableSlotResponse, CancelPreconfRequest, CancelPreconfResponse, PreconfHash,
    PreconfRequest, PreconfResponse, PreconfStatusResponse, PreconfTxRequest,
};
use serde::{Deserialize, Serialize};

use crate::{error::RpcError, preconf_api::PreconfState, pricer::PreconfPricer};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetPreconfRequestQuery {
    preconf_hash: PreconfHash,
}

#[allow(dead_code)]
pub struct PreconfBuilderApi;

impl<T, P, F> BuilderApi<PreconfState<T, P, F>> for PreconfBuilderApi
where
    T: Transport + Clone + Send + Sync + 'static,
    P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
    F: PreconfPricer + Clone + Send + Sync + 'static,
{
    /// Use to extend the BuilderApi
    fn extra_routes() -> Option<Router<PbsState<PreconfState<T, P, F>>>> {
        Some(
            Router::new()
                .route("/commitments/v1/preconf_request", post(handle_preconf_request))
                .route("/commitments/v1/preconf_request", delete(delete_preconf_request))
                .route("/commitments/v1/preconf_request/tx", post(handle_preconf_request_tx))
                .route("/commitments/v1/preconf_request/:preconf_hash", get(get_preconf_request))
                .route("/commitments/v1/slots", get(get_slots)),
        )
    }
}

pub async fn handle_preconf_request<T, P, F>(
    State(state): State<PbsState<PreconfState<T, P, F>>>,
    Json(preconf_request): Json<PreconfRequest>,
) -> Result<Json<PreconfResponse>, RpcError>
where
    T: Transport + Clone + Send + Sync + 'static,
    P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
    F: PreconfPricer + Clone + Send + Sync + 'static,
{
    Ok(Json(state.data.send_preconf_request(preconf_request).await?))
}
pub async fn delete_preconf_request<T, P, F>(
    State(state): State<PbsState<PreconfState<T, P, F>>>,
    Json(cancel_request): Json<CancelPreconfRequest>,
) -> Result<Json<CancelPreconfResponse>, RpcError>
where
    T: Transport + Clone + Send + Sync + 'static,
    P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
    F: PreconfPricer + Clone + Send + Sync + 'static,
{
    Ok(Json(state.data.cancel_preconf_request(cancel_request).await?))
}

pub async fn handle_preconf_request_tx<T, P, F>(
    State(state): State<PbsState<PreconfState<T, P, F>>>,
    Json(request): Json<PreconfTxRequest>,
) -> Result<impl IntoResponse, RpcError>
where
    T: Transport + Clone + Send + Sync + 'static,
    P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
    F: PreconfPricer + Clone + Send + Sync + 'static,
{
    Ok(Json(state.data.send_preconf_tx_request(request.preconf_hash, request.tx).await?))
}
pub async fn get_preconf_request<T, P, F>(
    State(state): State<PbsState<PreconfState<T, P, F>>>,
    Path(params): Path<GetPreconfRequestQuery>,
) -> Result<Json<PreconfStatusResponse>, RpcError>
where
    T: Transport + Clone + Send + Sync + 'static,
    P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
    F: PreconfPricer + Clone + Send + Sync + 'static,
{
    Ok(Json(state.data.check_preconf_request_status(params.preconf_hash).await?))
}
pub async fn get_slots<T, P, F>(
    State(state): State<PbsState<PreconfState<T, P, F>>>,
) -> Result<Json<AvailableSlotResponse>, RpcError>
where
    T: Transport + Clone + Send + Sync + 'static,
    P: Provider<T, Ethereum> + Clone + Send + Sync + 'static,
    F: PreconfPricer + Clone + Send + Sync + 'static,
{
    Ok(Json(state.data.available_slot().await?))
}
