use crate::{pbs::BuilderEvent, utils::get_user_agent};
use axum::{extract::State, http::HeaderMap, response::IntoResponse};
use reqwest::StatusCode;
use tracing::{error, info};

use crate::pbs::{
    api::BuilderApi,
    routes::PbsClientError,
    //    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsStateGuard},
};

//const RELOAD_ENDPOINT_TAG: &str = "reload";

pub async fn handle_reload<S: BuilderApiState, A: BuilderApi<S>>(
    req_headers: HeaderMap,
    State(state): State<PbsStateGuard<S>>,
) -> Result<impl IntoResponse, PbsClientError> {
    let prev_state = state.read().clone();

    prev_state.publish_event(BuilderEvent::ReloadEvent);

    let ua = get_user_agent(&req_headers);

    info!(ua, relay_check = prev_state.config.pbs_config.relay_check);

    match A::reload(prev_state.clone()).await {
        Ok(new_state) => {
            prev_state.publish_event(BuilderEvent::ReloadResponse);
            info!("config reload successful");

            *state.write() = new_state;

            //            BEACON_NODE_STATUS.with_label_values(&["200", RELOAD_ENDPOINT_TAG]).inc();
            Ok((StatusCode::OK, "OK"))
        }
        Err(err) => {
            error!(%err, "config reload failed");

            let err = PbsClientError::Internal;
            // BEACON_NODE_STATUS
            //     .with_label_values(&[err.status_code().as_str(), RELOAD_ENDPOINT_TAG])
            //     .inc();
            Err(err)
        }
    }
}
