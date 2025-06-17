use crate::{pbs::BuilderEvent, utils::get_user_agent};
use alloy::rpc::types::beacon::relay::ValidatorRegistration;
use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use reqwest::StatusCode;
use tracing::{error, info, trace};

use crate::pbs::{
    api::BuilderApi,
    //    constants::REGISTER_VALIDATOR_ENDPOINT_TAG,
    routes::PbsClientError,
    //    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsStateGuard},
};

// const REGISTER_VALIDATOR_ENDPOINT_TAG: &str = "register_validator";

pub async fn handle_register_validator<S: BuilderApiState, A: BuilderApi<S>>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    Json(registrations): Json<Vec<ValidatorRegistration>>,
) -> Result<impl IntoResponse, PbsClientError> {
    let state = state.read().clone();

    trace!(?registrations);
    state.publish_event(BuilderEvent::RegisterValidatorRequest(registrations.clone()));

    let ua = get_user_agent(&req_headers);

    info!(ua, num_registrations = registrations.len(), "new request");

    if let Err(err) = A::register_validator(registrations, req_headers, state.clone()).await {
        state.publish_event(BuilderEvent::RegisterValidatorResponse);
        error!(%err, "all relays failed registration");

        let err = PbsClientError::NoResponse;
        // BEACON_NODE_STATUS
        //     .with_label_values(&[err.status_code().as_str(), REGISTER_VALIDATOR_ENDPOINT_TAG])
        //     .inc();
        Err(err)
    } else {
        info!("register validator successful");

        // BEACON_NODE_STATUS.with_label_values(&["200", REGISTER_VALIDATOR_ENDPOINT_TAG]).inc();
        Ok(StatusCode::OK)
    }
}
