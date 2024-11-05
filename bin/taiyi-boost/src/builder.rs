use alloy_rpc_types_beacon::relay::ValidatorRegistration;
use async_trait::async_trait;
use axum::{http::HeaderMap, Router};
use cb_common::pbs::{
    GetHeaderParams, GetHeaderResponse, SignedBlindedBeaconBlock, SubmitBlindedBlockResponse,
};
use cb_pbs::{get_header, register_validator, submit_block};
use commit_boost::prelude::*;
use eyre::Result;

use crate::{constraints::ConstraintsCache, types::ExtraConfig};

#[allow(unused)]
#[derive(Clone)]
pub struct SidecarBuilderState {
    config: ExtraConfig,
    constraints: ConstraintsCache,
}

impl BuilderApiState for SidecarBuilderState {}

impl SidecarBuilderState {
    pub fn from_config(extra: &ExtraConfig) -> Self {
        Self { config: extra.clone(), constraints: ConstraintsCache::new() }
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
        get_header(params, req_headers, state).await
    }

    async fn submit_block(
        signed_blinded_block: SignedBlindedBeaconBlock,
        req_headers: HeaderMap,
        state: PbsState<SidecarBuilderState>,
    ) -> Result<SubmitBlindedBlockResponse> {
        submit_block(signed_blinded_block, req_headers, state).await
    }

    fn extra_routes() -> Option<Router<PbsState<SidecarBuilderState>>> {
        let router = Router::new();
        Some(router)
    }
}
