use builder::{SidecarBuilderApi, SidecarBuilderState};
use commit_boost::prelude::{load_pbs_custom_config, PbsService, PbsState};
use eyre::Result;
use taiyi_cmd::initialize_tracing_log;
use types::ExtraConfig;

mod beacon;
mod block_builder;
mod builder;
mod constraints;
mod engine;
mod engine_hinter;
mod error;
mod execution;
mod metrics;
mod proofs;
mod types;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    let (pbs_config, extra) = load_pbs_custom_config::<ExtraConfig>().await?;
    initialize_tracing_log();

    let sidecar_state = SidecarBuilderState::new(&extra).await;
    let pbs_state = PbsState::new(pbs_config.clone()).with_data(sidecar_state);

    metrics::init_metrics(pbs_config.chain)?;

    PbsService::run::<SidecarBuilderState, SidecarBuilderApi>(pbs_state).await?;

    Ok(())
}
