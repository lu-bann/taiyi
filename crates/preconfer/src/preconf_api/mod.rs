use std::net::{IpAddr, SocketAddr};

use alloy_primitives::Address;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use api::PreconfApiServer;
use blst::min_pk::SecretKey;
use ethereum_consensus::{clock, deneb::Context, phase0::mainnet::SLOTS_PER_EPOCH};
use state::PreconfState;
use tracing::{error, info};

use crate::{
    constraint_client::ConstraintClient,
    lookahead_fetcher::run_cl_process,
    network_state::NetworkState,
    preconfer::Preconfer,
    pricer::{ExecutionClientFeePricer, TaiyiFeePricer},
};

mod api;
pub mod state;

#[allow(clippy::too_many_arguments)]
pub async fn spawn_service(
    taiyi_escrow_contract_addr: Address,
    taiyi_core_contract_addr: Address,
    taiyi_proposer_registry_contract_addr: Address,
    execution_client_url: String,
    beacon_client_url: String,
    taiyi_service_url: Option<String>,
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
    let network_state = NetworkState::new(0, 0, Vec::new());
    let network_state_cl = network_state.clone();
    let constraint_client = ConstraintClient::new("titanrelay".to_string())?;

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

    let genesis_time = match context.genesis_time() {
        Ok(genesis_time) => genesis_time,
        Err(_) => context.min_genesis_time + context.genesis_delay,
    };
    let slot_stream =
        clock::from_system_time(genesis_time, context.seconds_per_slot, SLOTS_PER_EPOCH)
            .into_stream();

    info!("preconfer is on chain_id: {:?}", chain_id);
    match taiyi_service_url {
        Some(url) => {
            let base_fee_fetcher = TaiyiFeePricer::new(url.to_string());
            let validator = Preconfer::new(
                provider,
                taiyi_escrow_contract_addr,
                taiyi_core_contract_addr,
                base_fee_fetcher,
            );
            let state = PreconfState::new(
                execution_client_url,
                validator,
                network_state,
                constraint_client,
                context,
                bls_private_key,
                ecdsa_signer,
            )
            .await;

            // spawn preconfapi server
            let preconfapiserver =
                PreconfApiServer::new(SocketAddr::new(preconfer_ip, preconfer_port));
            preconfapiserver.run(state.clone()).await?;

            tokio::select! {
                _ = state.spawn_orderpool_cleaner(slot_stream) => {
                    error!("Orderpool cleaner task exited.");
                },
                _ = state.spawn_constraint_submitter() => {
                    error!("Constraint submitter task exited.");
                },
            }
        }
        None => {
            let base_fee_fetcher = ExecutionClientFeePricer::new(provider.clone());
            let validator = Preconfer::new(
                provider,
                taiyi_escrow_contract_addr,
                taiyi_core_contract_addr,
                base_fee_fetcher,
            );
            let state = PreconfState::new(
                execution_client_url,
                validator,
                network_state,
                constraint_client,
                context,
                bls_private_key,
                ecdsa_signer,
            )
            .await;

            // spawn preconfapi server
            let preconfapiserver =
                PreconfApiServer::new(SocketAddr::new(preconfer_ip, preconfer_port));
            preconfapiserver.run(state.clone()).await?;

            tokio::select! {
                res = state.spawn_orderpool_cleaner(slot_stream) => {
                    error!("Orderpool cleaner task exited. {:?}", res);
                },
                res = state.spawn_constraint_submitter() => {
                    error!("Constraint submitter task exited. {:?}", res);
                },
            }
        }
    };

    Ok(())
}
