use builder::{SidecarBuilderApi, SidecarBuilderState};
use commit_boost::prelude::*;
use eyre::Result;
use types::ExtraConfig;

mod block_builder;
mod builder;
mod constraints;
mod engine;
mod metrics;
mod proofs;
mod types;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    let (pbs_config, extra) = load_pbs_custom_config::<ExtraConfig>()?;
    let _guard = initialize_pbs_tracing_log()?;

    let sidecar_state = SidecarBuilderState::new(&extra).await;
    let pbs_state = PbsState::new(pbs_config.clone()).with_data(sidecar_state);

    metrics::init_metrics()?;

    PbsService::run::<SidecarBuilderState, SidecarBuilderApi>(pbs_state).await?;

    Ok(())
}
