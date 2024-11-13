use std::net::{IpAddr, SocketAddr};

use alloy_primitives::Address;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use api::PreconfApiServer;
use blst::min_pk::SecretKey;
use ethereum_consensus::deneb::Context;
use state::PreconfState;
use tracing::{error, info};

use crate::{
    constraint_client::ConstraintClient,
    lookahead_fetcher::run_cl_process,
    network_state::NetworkState,
    pricer::{ExecutionClientFeePricer, TaiyiFeePricer},
};

mod api;
pub mod state;

#[allow(clippy::too_many_arguments)]
pub async fn spawn_service(
    taiyi_proposer_registry_contract_addr: Address,
    execution_client_url: String,
    beacon_client_url: String,
    context: Context,
    preconfer_ip: IpAddr,
    preconfer_port: u16,
    bls_private_key: SecretKey,
    ecdsa_signer: PrivateKeySigner,
    relay_url: Vec<String>,
) -> eyre::Result<()> {
    let provider =
        ProviderBuilder::new().with_recommended_fillers().on_builtin(&execution_client_url).await?;
    let chain_id = provider.get_chain_id().await?;
    let provider_cl = provider.clone();
    let network_state = NetworkState::new(0, Vec::new());
    let network_state_cl = network_state.clone();
    let constraint_client = ConstraintClient::new(relay_url.clone())?;

    let bls_pk = bls_private_key.sk_to_pk();

    tokio::spawn(async move {
        if let Err(e) = run_cl_process(
            provider_cl,
            beacon_client_url,
            taiyi_proposer_registry_contract_addr,
            network_state_cl,
            bls_pk,
            relay_url,
        )
        .await
        {
            eprintln!("Error in cl process: {e:?}");
        }
    });

    info!("preconfer is on chain_id: {:?}", chain_id);

    let state =
        PreconfState::new(network_state, constraint_client, context, bls_private_key, ecdsa_signer)
            .await;

    // spawn preconfapi server
    let preconfapiserver = PreconfApiServer::new(SocketAddr::new(preconfer_ip, preconfer_port));
    let _ = preconfapiserver.run(state.clone()).await;

    tokio::select! {
        _ = state.spawn_constraint_submitter() => {
            error!("Constraint submitter task exited.");
        },

    }

    Ok(())
}
