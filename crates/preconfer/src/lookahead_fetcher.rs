use std::{ops::Deref, sync::Arc};

use alloy::rpc::types::beacon::events::HeadEvent;
use alloy::{
    core::primitives::{Address, Bytes},
    network::Ethereum,
    providers::Provider,
    sol,
    transports::Transport,
};
use beacon_api_client::{mainnet::Client, BlockId, ProposerDuty};
use futures::TryStreamExt;
use mev_share_sse::EventClient;
use parking_lot::RwLock;
use reqwest::Url;
use tokio::sync::mpsc::Sender;
use tracing::{debug, info};
use LubanProposerRegistry::LubanProposerRegistryInstance;

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
    _sender: Sender<Vec<ProposerDuty>>,
    _luban_proposer_registry_contract: LubanProposerRegistryInstance<T, P>,
    current_epoch: u64,
    current_slot: u64,
    proposers: Arc<RwLock<Vec<ProposerDuty>>>,
}

impl<T, P> LookaheadFetcher<T, P>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
{
    pub fn new(
        provider: P,
        beacon_url: String,
        sender: Sender<Vec<ProposerDuty>>,
        luban_proposer_registry_contract_addr: Address,
    ) -> Self {
        Self {
            client: Client::new(Url::parse(&beacon_url).expect("Invalid URL")),
            _sender: sender,
            _luban_proposer_registry_contract: LubanProposerRegistryInstance::new(
                luban_proposer_registry_contract_addr,
                provider,
            ),
            current_epoch: 0,
            current_slot: 0,
            proposers: Default::default(),
        }
    }

    pub async fn initialze(&mut self) -> eyre::Result<()> {
        let head = self.client.get_beacon_block(BlockId::Head).await?;
        let slot = head.message().slot();
        let epoch = slot / 32;
        self.update_proposer_duties(epoch).await?;
        self.current_slot = slot;
        self.current_epoch = epoch;
        Ok(())
    }

    async fn update_proposer_duties(&mut self, epoch: u64) -> eyre::Result<()> {
        let (_, duties) = self.client.get_proposer_duties(epoch).await?;
        let mut proposer_duties: Vec<ProposerDuty> = Vec::with_capacity(SLOT_PER_EPOCH as usize);

        for duty in duties.into_iter() {
            if duty.slot > self.current_slot {
                let pubkey = duty.public_key.clone();
                let proposer_status = self
                    ._luban_proposer_registry_contract
                    .getProposerStatus(Bytes::from(pubkey.deref().to_vec()))
                    .call()
                    .await?;
                if let ProposerStatus::OptIn = proposer_status._0 {
                    proposer_duties.push(ProposerDuty {
                        public_key: duty.public_key.clone(),
                        validator_index: duty.validator_index,
                        slot: duty.slot,
                    });
                }
            }
        }
        info!("Get the proposer duties: {:?}", proposer_duties);
        {
            let mut proposers = self.proposers.write();
            *proposers = proposer_duties;
        }

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
            info!(
                "Received event: current: {}, epoch: {}, epoch_transition: {}",
                self.current_epoch, epoch, event.epoch_transition
            );
            assert!(
                (epoch != self.current_epoch) == event.epoch_transition,
                "Invalid epoch"
            );
            if epoch != self.current_epoch {
                info!("Epoch changed from {} to {}", self.current_epoch, epoch);
                self.update_proposer_duties(epoch).await?;
                self.current_epoch = epoch;
            }
            self.current_slot = slot;
            info!("Current slot: {}", self.current_slot);
        }

        Ok(())
    }
}
