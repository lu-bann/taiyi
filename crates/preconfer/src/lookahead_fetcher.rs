use std::ops::Deref;

use alloy::rpc::types::beacon::events::HeadEvent;
use alloy::{
    core::primitives::{Address, Bytes},
    network::Ethereum,
    providers::Provider,
    sol,
    transports::Transport,
};
use beacon_api_client::{mainnet::Client, BlockId};
use futures::TryStreamExt;
use luban_primitives::ProposerInfo;
use mev_share_sse::EventClient;
use reqwest::Url;
use tracing::{debug, info};
use LubanProposerRegistry::LubanProposerRegistryInstance;

use crate::network_state::NetworkState;

const SLOT_PER_EPOCH: u64 = 32;

sol! {
    #[derive(Debug)]
    enum ProposerStatus {
        OptedOut,
        OptIn,
        OptingOut
    }

    #[sol(rpc)]
    contract LubanProposerRegistry {
        #[derive(Debug)]
        function getProposerStatus(bytes calldata blsPubKey) external view returns (ProposerStatus);
    }
}

pub struct LookaheadFetcher<T, P> {
    client: Client,
    luban_proposer_registry_contract: LubanProposerRegistryInstance<T, P>,
    network_state: NetworkState,
}

impl<T, P> LookaheadFetcher<T, P>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
{
    pub fn new(
        provider: P,
        beacon_url: String,
        luban_proposer_registry_contract_addr: Address,
        network_state: NetworkState,
    ) -> Self {
        Self {
            client: Client::new(Url::parse(&beacon_url).expect("Invalid URL")),
            luban_proposer_registry_contract: LubanProposerRegistryInstance::new(
                luban_proposer_registry_contract_addr,
                provider,
            ),
            network_state,
        }
    }

    pub async fn initialze(&mut self) -> eyre::Result<()> {
        let head = self.client.get_beacon_block(BlockId::Head).await?;
        let slot = head.message().slot();
        let epoch = slot / 32;
        self.update_proposer_duties(epoch).await?;
        self.network_state.update_slot(slot);
        self.network_state.update_epoch(epoch);
        Ok(())
    }

    async fn update_proposer_duties(&mut self, epoch: u64) -> eyre::Result<()> {
        let (_, duties) = self.client.get_proposer_duties(epoch).await?;
        let mut proposer_duties: Vec<ProposerInfo> = Vec::with_capacity(SLOT_PER_EPOCH as usize);

        for duty in duties.into_iter() {
            if duty.slot > self.network_state.get_current_slot() {
                let pubkey = duty.public_key.clone();
                let proposer_status = self
                    .luban_proposer_registry_contract
                    .getProposerStatus(Bytes::from(pubkey.deref().to_vec()))
                    .call()
                    .await?;
                if let ProposerStatus::OptIn = proposer_status._0 {
                    proposer_duties.push(duty.into());
                }
            }
        }
        info!("Get the proposer duties: {:?}", proposer_duties);
        self.network_state.update_proposer_duties(proposer_duties);

        Ok(())
    }

    pub async fn run(&mut self) -> eyre::Result<()> {
        let client = EventClient::new(reqwest::Client::default());
        let beacon_url_head_event =
            format!("{}eth/v1/events?topics=head", self.client.endpoint.as_str());
        info!("Starts to subscribe to {}", beacon_url_head_event);
        let mut stream: mev_share_sse::client::EventStream<HeadEvent> =
            client.subscribe(&beacon_url_head_event).await?;
        while let Some(event) = stream.try_next().await? {
            debug!("Received event: {:?}", event);
            let slot = event.slot;
            let epoch = slot / SLOT_PER_EPOCH;
            let current_epoch = self.network_state.get_current_epoch();
            info!(
                "Received event: current: {}, epoch: {}, epoch_transition: {}",
                current_epoch, epoch, event.epoch_transition
            );
            assert!(
                (epoch != current_epoch) == event.epoch_transition,
                "Invalid epoch"
            );
            if epoch != current_epoch {
                info!("Epoch changed from {} to {}", current_epoch, epoch);
                self.update_proposer_duties(epoch).await?;
                self.network_state.update_epoch(epoch);
            }
            self.network_state.update_slot(slot);
            info!("Current slot: {}", slot);
        }

        Ok(())
    }
}
