use std::{collections::HashMap, sync::Arc};

use alloy_primitives::{Address, U256};
use alloy_provider::{Provider, ProviderBuilder};
use api::PreconfBuilderApi;
use cb_common::{
    config::{load_from_file, CommitBoostConfig, PbsModuleConfig},
    pbs::{BuilderEventPublisher, RelayClient},
};
use cb_pbs::{PbsService, PbsState};
use ethereum_consensus::{clock, deneb::Context, phase0::mainnet::SLOTS_PER_EPOCH};
use state::PreconfState;
use tracing::info;

use crate::{
    constraint_client::ConstraintClient,
    lookahead_fetcher::run_cl_process,
    network_state::NetworkState,
    preconfer::Preconfer,
    pricer::{ExecutionClientFeePricer, LubanFeePricer},
    signer_client::SignerClient,
};

mod api;
pub mod state;

#[allow(clippy::too_many_arguments)]
pub async fn spawn_service(
    luban_escrow_contract_addr: Address,
    luban_core_contract_addr: Address,
    luban_proposer_registry_contract_addr: Address,
    rpc_url: String,
    beacon_rpc_url: String,
    luban_service_url: Option<String>,
    signer_mod_url: String,
    signer_mod_jwt: String,
    commit_boost_config_path: String,
    context: Context,
) -> eyre::Result<()> {
    let cb_config: CommitBoostConfig = load_from_file(&commit_boost_config_path)?;
    let relay_clients = cb_config
        .relays
        .clone()
        .into_iter()
        .map(RelayClient::new)
        .collect::<eyre::Result<Vec<_>>>()?;
    let maybe_publiher = BuilderEventPublisher::new_from_env();
    let pbs_config = PbsModuleConfig {
        chain: cb_config.chain,
        pbs_config: Arc::new(cb_config.pbs.pbs_config),
        relays: relay_clients.clone(),
        signer_client: None,
        event_publiher: maybe_publiher,
    };

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_builtin(&rpc_url)
        .await?;
    let chain_id = provider.get_chain_id().await?;
    let provider_cl = provider.clone();
    let network_state = NetworkState::new(0, 0, Vec::new());
    let network_state_cl = network_state.clone();

    let signer_client = SignerClient::new(signer_mod_url, U256::from(chain_id), signer_mod_jwt);

    let constraint_client = ConstraintClient::new(
        cb_config
            .relays
            .first()
            .cloned()
            .expect("at least one relay")
            .entry
            .url
            .to_string(),
    )?;
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

    let genesis_time = match context.genesis_time() {
        Ok(genesis_time) => genesis_time,
        Err(_) => context.min_genesis_time + context.genesis_delay,
    };
    let slot_stream =
        clock::from_system_time(genesis_time, context.seconds_per_slot, SLOTS_PER_EPOCH)
            .into_stream();

    // pubkeys.proxy should be empty since no proxy keys is generated on intialization
    let mut proxy_key_map = HashMap::new();
    if pubkeys.proxy.is_empty() {
        for pubkey in pubkeys.consensus {
            let proxy_delegation = signer_client
                .cb_signer_client()
                .generate_proxy_key(pubkey)
                .await?;
            proxy_key_map.insert(pubkey, proxy_delegation.message.proxy);
        }
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
                proxy_key_map,
                rpc_url,
                validator,
                network_state,
                signer_client,
                constraint_client,
                context,
            )
            .await;
            let _orderpool_cleaner_handle = state.spawn_orderpool_cleaner(slot_stream);
            let _constraint_submitter_handle = state.clone().spawn_constraint_submitter();

            let pbs_state = PbsState::new(pbs_config).with_data(state);
            PbsService::init_metrics()?;
            PbsService::run::<PreconfState<_, _, _>, PreconfBuilderApi>(pbs_state).await?;
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
                proxy_key_map,
                rpc_url,
                validator,
                network_state,
                signer_client,
                constraint_client,
                context,
            )
            .await;
            let _orderpool_cleaner_handle = state.spawn_orderpool_cleaner(slot_stream);
            let _constraint_submitter_handle = state.clone().spawn_constraint_submitter();

            let pbs_state = PbsState::new(pbs_config).with_data(state.clone());

            PbsService::init_metrics()?;
            PbsService::run::<PreconfState<_, _, _>, PreconfBuilderApi>(pbs_state).await?;
        }
    };

    Ok(())
}
