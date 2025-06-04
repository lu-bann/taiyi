use std::sync::Arc;

use builder::{SidecarBuilderApi, SidecarBuilderState};
use commit_boost::prelude::{load_pbs_custom_config, PbsService, PbsState};
use constraints::subscribe_to_constraints_stream;
use eyre::Result;
use futures::future::join_all;
use taiyi_cmd::initialize_tracing_log;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
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

    let cancel_token = CancellationToken::new();

    let constraints_cache = Arc::new(sidecar_state.constraints.clone());

    let cleanup_handle = constraints_cache.spawn_cleanup_task(cancel_token.clone());
    let relay_handles = subscribe_to_constraints_stream(
        constraints_cache,
        pbs_state.all_relays().to_vec(),
        cancel_token.clone(),
    )
    .await?;

    metrics::init_metrics(pbs_config.chain)?;

    tokio::select! {
        result = PbsService::run::<SidecarBuilderState, SidecarBuilderApi>(pbs_state) => {
            if let Err(e) = result {
                error!("PBS service error: {:?}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
    }

    cancel_token.cancel();

    let all_handles = {
        let mut handles = relay_handles;
        handles.push(cleanup_handle);
        handles
    };
    join_all(all_handles).await;

    info!("Shutting down taiyi-boost");

    Ok(())
}
