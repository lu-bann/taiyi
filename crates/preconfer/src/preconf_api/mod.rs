use std::net::{IpAddr, SocketAddr};

use alloy_primitives::Address;
use alloy_provider::{Provider, ProviderBuilder};
use api::PreconfApiServer;
use ethereum_consensus::deneb::Context;
use reqwest::Url;
use state::PreconfState;
use tracing::{error, info};

use crate::{
    clients::{
        pricer::{ExecutionClientPricer, Pricer, TaiyiPricer},
        relay_client::RelayClient,
        signer_client::SignerClient,
    },
    constraint_submit::spawn_constraint_submitter,
    lookahead_fetcher::run_cl_process,
    network_state::NetworkState,
};

pub mod api;
pub mod state;

#[allow(clippy::too_many_arguments)]
pub async fn spawn_service(
    execution_rpc_url: String,
    beacon_rpc_url: String,
    context: Context,
    preconfer_ip: IpAddr,
    preconfer_port: u16,
    bls_sk: String,
    ecdsa_sk: String,
    relay_url: Vec<Url>,
    taiyi_escrow_address: Address,
    taiyi_service_url: Option<String>,
) -> eyre::Result<()> {
    let provider =
        ProviderBuilder::new().with_recommended_fillers().on_builtin(&execution_rpc_url).await?;
    let chain_id = provider.get_chain_id().await?;

    let network_state = NetworkState::new(context.clone());
    let network_state_cl = network_state.clone();

    let relay_client = RelayClient::new(relay_url.clone());
    let signer_client = SignerClient::new(bls_sk, ecdsa_sk)?;
    let bls_pk = signer_client.bls_pubkey();

    info!("preconfer is on chain_id: {:?}", chain_id);

    match taiyi_service_url {
        Some(url) => {
            info!("Using Taiyi service at {}", url);
            let pricer = Pricer::new(TaiyiPricer::new(url, chain_id));
            let state = PreconfState::new(
                network_state,
                relay_client,
                signer_client,
                Url::parse(&execution_rpc_url)?,
                taiyi_escrow_address,
                provider,
                pricer,
            );
            let preconf_pool_clone = state.preconf_pool.clone();

            // spawn preconfapi server
            let preconfapiserver =
                PreconfApiServer::new(SocketAddr::new(preconfer_ip, preconfer_port));
            let _ = preconfapiserver.run(state.clone()).await;

            tokio::select! {
                    res = run_cl_process(beacon_rpc_url, network_state_cl, bls_pk, relay_url).await => {
                        error!("Error in cl process: {:?}", res);
                    }
                    res = spawn_constraint_submitter(state) => {
                        error!("Constraint submitter task exited. {:?}", res);
                    },
                    res = preconf_pool_clone.state_cache_cleanup(context).await => {
                        error!("Error in state cache cleanup: {:#?}", res);
                    },
                    _ = tokio::signal::ctrl_c() => {
                        info!("Ctrl-C received, shutting down...");
                    },
            }
        }
        None => {
            info!("Using execution client pricer at {}", execution_rpc_url);
            let pricer = Pricer::new(ExecutionClientPricer::new(provider.clone()));
            let state = PreconfState::new(
                network_state,
                relay_client,
                signer_client,
                Url::parse(&execution_rpc_url)?,
                taiyi_escrow_address,
                provider,
                pricer,
            );
            let preconf_pool_clone = state.preconf_pool.clone();

            // spawn preconfapi server
            let preconfapiserver =
                PreconfApiServer::new(SocketAddr::new(preconfer_ip, preconfer_port));
            let _ = preconfapiserver.run(state.clone()).await;

            tokio::select! {
                    res = run_cl_process(beacon_rpc_url, network_state_cl, bls_pk, relay_url).await => {
                        error!("Error in cl process: {:?}", res);
                    }
                    res = spawn_constraint_submitter(state) => {
                        error!("Constraint submitter task exited. {:?}", res);
                    },
                    res = preconf_pool_clone.state_cache_cleanup(context).await => {
                        error!("Error in state cache cleanup: {:#?}", res);
                    },
                    _ = tokio::signal::ctrl_c() => {
                        info!("Ctrl-C received, shutting down...");
                    },
            }
        }
    }

    Ok(())
}
