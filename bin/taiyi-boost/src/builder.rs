#![allow(unused)]
use async_trait::async_trait;
use axum::Router;
use commit_boost::prelude::*;

use crate::types::ExtraConfig;

#[derive(Clone)]
pub struct SidecarBuilderState {
    config: ExtraConfig,
}

impl BuilderApiState for SidecarBuilderState {}

impl SidecarBuilderState {
    pub fn from_config(extra: &ExtraConfig) -> Self {
        Self { config: extra.clone() }
    }
}

pub struct SidecarBuilderApi;

#[async_trait]
impl BuilderApi<SidecarBuilderState> for SidecarBuilderApi {
    fn extra_routes() -> Option<Router<PbsState<SidecarBuilderState>>> {
        let router = Router::new();
        Some(router)
    }
}
