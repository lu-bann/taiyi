use std::sync::Arc;

use alloy::providers::{Provider, ProviderBuilder};
use api::PreconfBuilderApi;
use cb_common::{
    config::{load_from_file, CommitBoostConfig, PbsModuleConfig},
    pbs::{BuilderEventPublisher, RelayClient},
};
use cb_pbs::{PbsService, PbsState};
use ethereum_consensus::networks::Network;
use reth::primitives::{Address, U256};
use state::PreconfState;
use tracing::info;

use crate::{
    chainspec_builder::chainspec_builder,
    lookahead_fetcher::run_cl_process,
    network_state::NetworkState,
    preconfer::Preconfer,
    pricer::{ExecutionClientFeePricer, LubanFeePricer},
    signer_client::SignerClient,
};

mod api;
mod state;

#[allow(clippy::too_many_arguments)]
pub async fn spawn_service(
    network: Network,
    luban_escrow_contract_addr: Address,
    luban_core_contract_addr: Address,
    luban_proposer_registry_contract_addr: Address,
    rpc_url: String,
    beacon_rpc_url: String,
    luban_service_url: Option<String>,
    commit_boost_url: String,
    cb_id: String,
    cb_jwt: String,
    commit_boost_config_path: String,
) -> eyre::Result<()> {
    let cb_config: CommitBoostConfig = load_from_file(&commit_boost_config_path)?;
    let relay_clients = cb_config
        .relays
        .into_iter()
        .map(RelayClient::new)
        .collect::<eyre::Result<Vec<_>>>()?;
    let maybe_publiher = BuilderEventPublisher::new_from_env();
    let pbs_config = PbsModuleConfig {
        chain: cb_config.chain,
        pbs_config: Arc::new(cb_config.pbs.pbs_config),
        relays: relay_clients,
        signer_client: None,
        event_publiher: maybe_publiher,
    };

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_builtin(&rpc_url)
        .await?;
    let chain_id = provider.get_chain_id().await?;

    let chain_spec = chainspec_builder(network);

    let provider_cl = provider.clone();
    let network_state = NetworkState::new(0, 0, Vec::new());
    let network_state_cl = network_state.clone();

    let signer_client = SignerClient::new(commit_boost_url, U256::from(chain_id), cb_id, cb_jwt);
    let pubkeys = signer_client
        .get_pubkeys()
        .await
        .expect("pubkeys should be received.");
    let pubkeys_dup = pubkeys.consensus.clone();

    tokio::spawn(async move {
        if let Err(e) = run_cl_process(
            provider_cl,
            beacon_rpc_url,
            luban_proposer_registry_contract_addr,
            network_state_cl,
            pubkeys_dup,
        )
        .await
        {
            eprintln!("Error in cl process: {e:?}");
        }
    });

    let proxy_key = if pubkeys.proxy.is_empty() {
        let pubkey = pubkeys
            .consensus
            .first()
            .expect("pubkey should be received.");
        let proxy_delegation = signer_client
            .cb_signer_client()
            .generate_proxy_key(*pubkey)
            .await?;
        proxy_delegation.message.proxy
    } else {
        *pubkeys.proxy.first().expect("pubkey should be received.")
    };

    info!("preconfer is on chain_id: {:?}", chain_id);
    match luban_service_url {
        Some(url) => {
            let base_fee_fetcher = LubanFeePricer::new(url.to_string());
            let validator = Preconfer::new(
                provider,
                luban_escrow_contract_addr,
                luban_core_contract_addr,
                base_fee_fetcher,
            );
            let state = PreconfState::new(
                chain_spec,
                rpc_url,
                validator,
                network_state,
                proxy_key,
                signer_client,
            )
            .await;
            let pb_state = PbsState::new(pbs_config).with_data(state);

            PbsService::init_metrics()?;
            PbsService::run::<PreconfState<_, _, _>, PreconfBuilderApi>(pb_state).await?;
        }
        None => {
            let base_fee_fetcher = ExecutionClientFeePricer::new(provider.clone());
            let validator = Preconfer::new(
                provider,
                luban_escrow_contract_addr,
                luban_core_contract_addr,
                base_fee_fetcher,
            );
            let state = PreconfState::new(
                chain_spec,
                rpc_url,
                validator,
                network_state,
                proxy_key,
                signer_client,
            )
            .await;
            let state = PbsState::new(pbs_config).with_data(state);

            PbsService::init_metrics()?;
            PbsService::run::<PreconfState<_, _, _>, PreconfBuilderApi>(state).await?;
        }
    };

    Ok(())
}
