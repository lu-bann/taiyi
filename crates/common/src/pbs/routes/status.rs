use crate::{pbs::BuilderEvent, utils::get_user_agent};
use axum::{extract::State, http::HeaderMap, response::IntoResponse};
use reqwest::StatusCode;
use tracing::{error, info};

use crate::pbs::{
    api::BuilderApi,
    //    constants::STATUS_ENDPOINT_TAG,
    routes::PbsClientError,
    //    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsStateGuard},
};

const STATUS_ENDPOINT_TAG: &str = "status";

pub async fn handle_get_status<S: BuilderApiState, A: BuilderApi<S>>(
    req_headers: HeaderMap,
    State(state): State<PbsStateGuard<S>>,
) -> Result<impl IntoResponse, PbsClientError> {
    let state = state.read().clone();

    state.publish_event(BuilderEvent::GetStatusEvent);

    let ua = get_user_agent(&req_headers);

    info!(ua, relay_check = state.config.pbs_config.relay_check, "new request");

    match A::get_status(req_headers, state.clone()).await {
        Ok(_) => {
            state.publish_event(BuilderEvent::GetStatusResponse);
            info!("relay check successful");

            //            BEACON_NODE_STATUS.with_label_values(&["200", STATUS_ENDPOINT_TAG]).inc();
            Ok(StatusCode::OK)
        }
        Err(err) => {
            error!(%err, "all relays failed get_status");

            let err = PbsClientError::NoResponse;
            // BEACON_NODE_STATUS
            //     .with_label_values(&[err.status_code().as_str(), STATUS_ENDPOINT_TAG])
            //     .inc();
            Err(err)
        }
    }
}
