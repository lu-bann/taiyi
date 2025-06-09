use builder::{SidecarBuilderApi, SidecarBuilderState};
use commit_boost::prelude::{load_pbs_custom_config, PbsService, PbsState};
use constraints::subscribe_to_constraints_stream;
use eyre::Result;
use taiyi_cmd::initialize_tracing_log;
use tokio::join;
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
mod utils;

use crate::constraints::ConstraintsCache;

fn log_error<E: ToString>(result: Result<(),E>, msg: &str) {
    if let Err(err) = result {
        error!("{msg}: {}", err.to_string())
    }
}

async fn run_constraints_stream(constraints: ConstraintsCache, pbs_state: PbsState<SidecarBuilderState>) {
    loop {
        log_error(subscribe_to_constraints_stream(constraints.clone(), pbs_state.all_relays()).await, "Error in constraints stream");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let (pbs_config, extra) = load_pbs_custom_config::<ExtraConfig>().await?;
    initialize_tracing_log();

    let sidecar_state = SidecarBuilderState::new(&extra).await;
    let pbs_state = PbsState::new(pbs_config.clone()).with_data(sidecar_state.clone());

    metrics::init_metrics(pbs_config.chain)?;

    let _ = join!(
        run_constraints_stream(sidecar_state.constraints, pbs_state.clone()),
        PbsService::run::<SidecarBuilderState, SidecarBuilderApi>(pbs_state)
    );

    Ok(())
}
