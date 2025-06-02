use std::sync::Arc;

use builder::{SidecarBuilderApi, SidecarBuilderState};
use commit_boost::prelude::{load_pbs_custom_config, PbsService, PbsState};
use constraints::subscribe_to_constraints_stream;
use eyre::Result;
use taiyi_cmd::initialize_tracing_log;
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
mod utils;

pub use types::ConstraintsMessage;

#[tokio::main]
async fn main() -> Result<()> {
    let (pbs_config, extra) = load_pbs_custom_config::<ExtraConfig>().await?;
    initialize_tracing_log();

    let sidecar_state = SidecarBuilderState::new(&extra).await;
    let pbs_state = PbsState::new(pbs_config.clone()).with_data(sidecar_state.clone());

    let constraints_cache = Arc::new(sidecar_state.constraints.clone());
    subscribe_to_constraints_stream(
        constraints_cache,
        pbs_state.all_relays().to_vec(),
        extra.timeout,
    )
    .await?;

    metrics::init_metrics(pbs_config.chain)?;

    PbsService::run::<SidecarBuilderState, SidecarBuilderApi>(pbs_state).await?;

    Ok(())
}
