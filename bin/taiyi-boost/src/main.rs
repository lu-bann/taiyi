#![allow(unused_must_use)]
use builder::{SidecarBuilderApi, SidecarBuilderState};
use commit_boost::prelude::*;
use delegation::DelegationService;
use eyre::Result;

mod builder;
mod delegation;
mod sse;
mod types;
use sse::BeaconEventClient;
use tokio::{join, sync::mpsc};
use types::ExtraConfig;

#[tokio::main]
async fn main() -> Result<()> {
    let (pbs_config, extra) = load_pbs_custom_config::<ExtraConfig>()?;
    let _guard = initialize_pbs_tracing_log()?;

    let sidecar_state = SidecarBuilderState::from_config(&extra);
    let pbs_state = PbsState::new(pbs_config.clone()).with_data(sidecar_state);

    let (duties_tx, duties_rx) = mpsc::unbounded_channel();
    let beacon_event_client = BeaconEventClient::new(&extra.beacon_node, duties_tx);

    let delegator = DelegationService::new(
        extra.chain_id,
        extra.trusted_preconfer,
        pbs_config.signer_client.expect("signer client not found"),
        pbs_config.relays.clone(),
        duties_rx,
    );

    join!(
        PbsService::run::<SidecarBuilderState, SidecarBuilderApi>(pbs_state),
        beacon_event_client.run(),
        delegator.run()
    );

    Ok(())
}
