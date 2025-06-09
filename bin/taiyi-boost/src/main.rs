use builder::{SidecarBuilderApi, SidecarBuilderState};
use commit_boost::prelude::{load_pbs_custom_config, PbsService, PbsState};
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
mod utils;

fn log_error<E: ToString>(result: Result<(), E>, msg: &str) {
    if let Err(err) = result {
        error!("{msg}: {}", err.to_string());
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let (pbs_config, extra) = load_pbs_custom_config::<ExtraConfig>().await?;
    initialize_tracing_log();

    let sidecar_state = SidecarBuilderState::new(&extra).await;
    let pbs_state = PbsState::new(pbs_config.clone()).with_data(sidecar_state.clone());

    metrics::init_metrics(pbs_config.chain)?;

    loop {
        let result: Result<()> = select!(
            v = subscribe_to_constraints_stream(sidecar_state.constraints.clone(), pbs_state.all_relays()) => v,
            v = PbsService::run::<SidecarBuilderState, SidecarBuilderApi>(pbs_state.clone()) => v
        );
        log_error(result, "Taiyi Boost");
    }
}
