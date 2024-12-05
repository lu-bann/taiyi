use std::{sync::Arc, time::Duration};

use alloy_rpc_types_beacon::relay::ValidatorRegistration;
use async_trait::async_trait;
use axum::{http::HeaderMap, Router};
use cb_common::pbs::{
    GetHeaderParams, GetHeaderResponse, SignedBlindedBeaconBlock, SubmitBlindedBlockResponse,
    Version,
};
use cb_pbs::{get_header, register_validator, submit_block};
use commit_boost::prelude::*;
use ethereum_consensus::deneb::Context;
use eyre::Result;
use parking_lot::Mutex;
use tracing::warn;

use crate::{
    block_builder::{LocalBlockBuilder, SignedPayloadResponse},
    constraints::ConstraintsCache,
    types::{ExtraConfig, SignedConstraints, BUILDER_CONSTRAINTS_PATH},
};

#[allow(unused)]
#[derive(Clone)]
pub struct SidecarBuilderState {
    config: ExtraConfig,
    constraints: ConstraintsCache,
    local_block_builder: LocalBlockBuilder,
    local_payload: Arc<Mutex<Option<SignedPayloadResponse>>>,
}

impl BuilderApiState for SidecarBuilderState {}

impl SidecarBuilderState {
    pub async fn new(extra: &ExtraConfig) -> Self {
        let context: Context =
            extra.network.clone().try_into().expect("failed to convert network to context");

        let local_block_builder = LocalBlockBuilder::new(
            context,
            extra.beacon_api.clone(),
            extra.engine_api.clone(),
            extra.execution_api.clone(),
            extra.engine_jwt.0,
            extra.fee_recipient,
            extra.builder_private_key.clone().0,
        )
        .await;
        Self {
            config: extra.clone(),
            constraints: ConstraintsCache::new(),
            local_block_builder,
            local_payload: Arc::new(Mutex::new(None)),
        }
    }
}

pub struct SidecarBuilderApi;

#[async_trait]
impl BuilderApi<SidecarBuilderState> for SidecarBuilderApi {
    async fn register_validator(
        registrations: Vec<ValidatorRegistration>,
        req_headers: HeaderMap,
        state: PbsState<SidecarBuilderState>,
    ) -> Result<()> {
        let (slot, _) = state.get_slot_and_uuid();
        state.data.constraints.prune(slot);

        register_validator(registrations, req_headers, state).await
    }

    async fn get_header(
        params: GetHeaderParams,
        req_headers: HeaderMap,
        state: PbsState<SidecarBuilderState>,
    ) -> Result<Option<GetHeaderResponse>> {
        match get_header(params, req_headers, state.clone()).await {
            Ok(Some(response)) => {
                let mut local_payload = state.data.local_payload.lock();
                *local_payload = None;
                return Ok(Some(response));
            }
            Err(err) => {
                warn!("get header from relay failed, slot: {}, error: {}", params.slot, err);
            }
            _ => {
                warn!("get header from relay failed, slot: {}", params.slot);
            }
        }

        // get builder constraints from one of the relays
        for relay in state.relays() {
            let builder_constraints_url = relay
                .builder_api_url(BUILDER_CONSTRAINTS_PATH)
                .expect("failed to build builder_constraints url");
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Build reqwest client failed");
            match client
                .post(builder_constraints_url.clone())
                .query(&[("slot", params.slot.to_string())])
                .send()
                .await
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        match resp.json::<Vec<SignedConstraints>>().await {
                            Ok(constraints) => {
                                if constraints.is_empty() {
                                    warn!(
                                        "constraints is empty, url: {}, slot: {}",
                                        builder_constraints_url.to_string(),
                                        params.slot
                                    );
                                    continue;
                                }
                                if let Err(err) =
                                    state.data.constraints.insert(constraints[0].message.clone())
                                {
                                    warn!(
                                        "failed to insert constraints, slot: {}, error: {}",
                                        params.slot, err
                                    );
                                    continue;
                                }
                            }
                            Err(err) => {
                                warn!("failed to parse constraints from response, url: {}, slot: {}, error: {}", builder_constraints_url.to_string(), params.slot, err);
                                continue;
                            }
                        }
                        break;
                    }
                }
                Err(err) => {
                    warn!(
                        "get constraints from relay failed, url: {}, slot: {}, error: {}",
                        builder_constraints_url.to_string(),
                        params.slot,
                        err
                    );
                }
            }
        }
        // todo: error handling
        let transactions = state.data.constraints.get(params.slot).expect("constraints not found");
        let resp = state
            .data
            .local_block_builder
            .build_signed_payload_response(params.slot, &transactions)
            .await?;
        {
            let mut local_payload = state.data.local_payload.lock();
            *local_payload = Some(resp.clone());
        }
        Ok(Some(GetHeaderResponse { version: Version::Deneb, data: resp.header.clone() }))
    }

    async fn submit_block(
        signed_blinded_block: SignedBlindedBeaconBlock,
        req_headers: HeaderMap,
        state: PbsState<SidecarBuilderState>,
    ) -> Result<SubmitBlindedBlockResponse> {
        if let Some(local_payload) = state.data.local_payload.lock().take() {
            // todo: do some checks
            return Ok(SubmitBlindedBlockResponse {
                version: Version::Deneb,
                data: local_payload.payload.clone(),
            });
        }
        submit_block(signed_blinded_block, req_headers, state).await
    }

    fn extra_routes() -> Option<Router<PbsState<SidecarBuilderState>>> {
        let router = Router::new();
        Some(router)
    }
}
