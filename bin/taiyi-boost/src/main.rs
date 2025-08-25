use builder::{SidecarBuilderApi, SidecarBuilderState};
use cb_common::config::load_pbs_custom_config;
use cb_common::pbs::{service::PbsService, state::PbsState};
use constraints::subscribe_to_constraints_stream;
use eyre::Result;
use taiyi_cmd::initialize_tracing_log;
use tokio::select;
use tracing::error;
use types::ExtraConfig;

mod block_builder;
mod builder;
mod constraints;
mod engine;
mod engine_hinter;
mod error;
mod execution;
mod ext;
mod metrics;
mod proofs;
mod types;
use crate::block_builder::LocalBlockBuilder;

#[tokio::main]
async fn main() -> Result<()> {
    let (pbs_config, extra) = load_pbs_custom_config::<ExtraConfig>().await?;
    initialize_tracing_log();

    let genesis_time: u64 = 1;
    let seconds_per_slot: u64 = 2;
    let deneb_fork_version = [5, 1, 112, 0];

    let local_block_builder = LocalBlockBuilder::new(
        genesis_time,
        seconds_per_slot,
        extra.beacon_api.clone(),
        extra.engine_api.clone(),
        extra.execution_api.clone(),
        extra.engine_jwt.0,
        extra.fee_recipient,
        extra.builder_private_key.clone().0,
        extra.auth_token.clone(),
        deneb_fork_version,
    )
    .await;
    let sidecar_state = SidecarBuilderState::new(local_block_builder);
    let pbs_state = PbsState::new(pbs_config.clone()).with_data(sidecar_state.clone());

    metrics::init_metrics(pbs_config.chain)?;

    loop {
        let result: Result<()> = select!(
            v = subscribe_to_constraints_stream(sidecar_state.constraints.clone(), pbs_state.all_relays()) => v,
            v = PbsService::run::<SidecarBuilderState, SidecarBuilderApi>(pbs_state.clone()) => v
        );
        if let Err(err) = result {
            error!("Taiyi Boost: {}", err);
        }
    }
}
