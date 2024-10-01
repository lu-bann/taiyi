use std::ops::Deref;

use alloy_network::Ethereum;
use alloy_primitives::{Address, Bytes};
use alloy_provider::Provider;
use alloy_rpc_types_beacon::{events::HeadEvent, BlsPublicKey};
use alloy_sol_types::sol;
use alloy_transport::Transport;
use beacon_api_client::{mainnet::Client, BlockId};
use ethereum_consensus::{
    primitives::{BlsPublicKey as HelixPublicKey, BlsSignature},
    ssz::prelude::*,
};
use futures::TryStreamExt;
use mev_share_sse::EventClient;
use reqwest::Url;
use taiyi_primitives::ProposerInfo;
use tracing::{debug, info};
use TaiyiProposerRegistry::TaiyiProposerRegistryInstance;

use crate::network_state::NetworkState;

const SLOT_PER_EPOCH: u64 = 32;
pub(crate) const PATH_GET_PRECONFERS: &str = "/preconfers";

sol! {
    #[derive(Debug)]
    enum ProposerStatus {
        OptedOut,
        OptIn,
        OptingOut
    }

    #[sol(rpc)]
    contract TaiyiProposerRegistry {
        #[derive(Debug)]
        function getProposerStatus(bytes calldata blsPubKey) external view returns (ProposerStatus);
    }
}

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct SignedPreconferElection {
    pub message: PreconferElection,
    /// Signature over `message`. Must be signed by the key relating to: `message.public_key`.
    pub signature: BlsSignature,
}

#[derive(Debug, Default, Clone, SimpleSerialize, serde::Serialize, serde::Deserialize)]
pub struct PreconferElection {
    /// Public key of the preconfer proposing for `slot`.
    preconfer_pubkey: HelixPublicKey,
    /// Slot this delegation is valid for.
    slot_number: u64,
    /// Chain ID of the chain this election is for.
    chain_id: u64,
    // The gas limit specified by the proposer that the preconfer must adhere to.
    gas_limit: u64,
}

pub struct LookaheadFetcher<T, P> {
    client: Client,
    taiyi_proposer_registry_contract: TaiyiProposerRegistryInstance<T, P>,
    network_state: NetworkState,
    validator_pubkeys: Vec<BlsPublicKey>,
}

impl<T, P> LookaheadFetcher<T, P>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
{
    pub fn new(
        provider: P,
        beacon_url: String,
        taiyi_proposer_registry_contract_addr: Address,
        network_state: NetworkState,
        validator_pubkeys: Vec<BlsPublicKey>,
    ) -> Self {
        Self {
            client: Client::new(Url::parse(&beacon_url).expect("Invalid URL")),
            taiyi_proposer_registry_contract: TaiyiProposerRegistryInstance::new(
                taiyi_proposer_registry_contract_addr,
                provider,
            ),
            network_state,
            validator_pubkeys,
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
        let mut all_duties = Vec::with_capacity(64);

        let (_, duties) = self.client.get_proposer_duties(epoch).await?;
        all_duties.extend(duties);
        let (_, duties) = self.client.get_proposer_duties(epoch + 1).await?;
        all_duties.extend(duties);

        // fetch validator pubkeys we represent
        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}{PATH_GET_PRECONFERS}", "titan.relay"))
            .send()
            .await?
            .json::<Vec<SignedPreconferElection>>()
            .await?;

        // Change this to our preconfer pubkey
        let preconfer_pubkey = HelixPublicKey::default();
        let concerned_slots = response
            .into_iter()
            .filter(|signed_preconfer_election| {
                let preconfer_election = &signed_preconfer_election.message;
                preconfer_election.preconfer_pubkey == preconfer_pubkey
            })
            .map(|signed_preconfer_election| signed_preconfer_election.message.slot_number)
            .collect::<Vec<_>>();

        let duties = all_duties
            .into_iter()
            .filter(|duty| concerned_slots.contains(&duty.slot))
            .collect::<Vec<_>>();
        let mut proposer_duties: Vec<ProposerInfo> = Vec::new();

        for duty in duties.into_iter() {
            if duty.slot > self.network_state.get_current_slot() {
                let pubkey = duty.public_key.clone();
                let proposer_status = self
                    .taiyi_proposer_registry_contract
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
            assert!((epoch != current_epoch) == event.epoch_transition, "Invalid epoch");
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

pub async fn run_cl_process<T, P>(
    provider: P,
    beacon_url: String,
    taiyi_proposer_registry_contract_addr: Address,
    network_state: NetworkState,
) -> eyre::Result<()>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
{
    let mut lookahead_fetcher = LookaheadFetcher::new(
        provider,
        beacon_url,
        taiyi_proposer_registry_contract_addr,
        network_state,
        Vec::new(),
    );
    lookahead_fetcher.initialze().await?;
    lookahead_fetcher.run().await?;

    Ok(())
}
