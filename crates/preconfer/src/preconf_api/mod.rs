use std::net::{IpAddr, SocketAddr};

use alloy_primitives::Address;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use api::PreconfApiServer;
use blst::min_pk::SecretKey;
use ethereum_consensus::deneb::Context;
use reth_revm::handler::execution;
use state::PreconfState;
use tracing::{error, info};

use crate::{
    constraint_client::ConstraintClient,
    lookahead_fetcher::run_cl_process,
    metrics::provider,
    network_state::NetworkState,
    preconfer::Preconfer,
    pricer::{ExecutionClientFeePricer, TaiyiFeePricer},
};

mod api;
mod jsonrpc;
pub mod state;

#[allow(clippy::too_many_arguments)]
pub async fn spawn_service(
    execution_client_url: String,
    context: Context,
    preconfer_ip: IpAddr,
    preconfer_port: u16,
    bls_private_key: SecretKey,
    ecdsa_signer: PrivateKeySigner,
    relay_url: Vec<String>,
) -> eyre::Result<()> {
    let constraint_client =
        ConstraintClient::new(relay_url.first().expect("relay_url is empty").clone())?;

    let provider =
        ProviderBuilder::new().with_recommended_fillers().on_builtin(&execution_client_url).await?;

    let state = PreconfState::new(
        constraint_client,
        context,
        bls_private_key,
        ecdsa_signer,
        provider.clone(),
    )
    .await;

    // spawn preconfapi server
    let preconfapiserver = PreconfApiServer::new(SocketAddr::new(preconfer_ip, preconfer_port));
    let server_handle = preconfapiserver.run(state.clone()).await;

    tokio::select! {
        res = state.spawn_constraint_submitter() => {
            error!("Constraint submitter task exited. {:?}", res);
        },
    }

    Ok(())
}
