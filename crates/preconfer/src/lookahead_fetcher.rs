use std::ops::Deref;

use alloy_eips::merge::EPOCH_SLOTS;
use alloy_network::Ethereum;
use alloy_primitives::{Address, Bytes};
use alloy_provider::Provider;
use alloy_rpc_types_beacon::events::HeadEvent;
use alloy_sol_types::sol;
use alloy_transport::Transport;
use beacon_api_client::{mainnet::Client, BlockId};
use blst::min_pk::PublicKey;
use ethereum_consensus::{
    primitives::{BlsPublicKey, BlsSignature},
    ssz::prelude::*,
};
use futures::TryStreamExt;
use mev_share_sse::EventClient;
use reqwest::Url;
use taiyi_primitives::ProposerInfo;
use tracing::{debug, info};

use crate::{
    clients::relay_client::{RelayClient, DELEGATION_ACTION},
    network_state::NetworkState,
};

pub struct LookaheadFetcher {
    beacon_client: Client,
    network_state: NetworkState,
    gateway_pubkey: BlsPublicKey,
    relay_client: RelayClient,
}

impl LookaheadFetcher {
    pub fn new(
        beacon_url: String,
        network_state: NetworkState,
        gateway_pubkey: PublicKey,
        relay_urls: Vec<Url>,
    ) -> Self {
        let gateway_pubkey =
            BlsPublicKey::try_from(gateway_pubkey.to_bytes().as_ref()).expect("Invalid public key");
        Self {
            beacon_client: Client::new(Url::parse(&beacon_url).expect("Invalid URL")),
            network_state,
            gateway_pubkey,
            relay_client: RelayClient::new(relay_urls),
        }
    }

    pub async fn initialze(&mut self) -> eyre::Result<()> {
        let head = self.beacon_client.get_beacon_block(BlockId::Head).await?;
        let slot = head.message().slot();
        let epoch = slot / 32;
        self.add_slot(epoch).await?;
        self.network_state.update_slot(slot);
        Ok(())
    }

    /// Add slots from the epoch if the slot is delegated to the gateway
    async fn add_slot(&mut self, epoch: u64) -> eyre::Result<()> {
        // Fetch delegations for every slot in next epoch
        for slot in (epoch * 32)..((epoch + 1) * 32) {
            let signed_delegations = self.relay_client.get_delegations(slot).await?;
            for signed_delegation in signed_delegations {
                let delegation_message = signed_delegation.message;
                if delegation_message.action == DELEGATION_ACTION
                    && delegation_message.delegatee_pubkey == self.gateway_pubkey
                {
                    info!("Delegation to gateway found for slot: {}", slot);
                    self.network_state.add_slot(slot);
                }
            }
        }

        // clear old slots
        self.network_state.clear_slots(epoch);

        Ok(())
    }

    pub async fn run(&mut self) -> eyre::Result<()> {
        let client = EventClient::new(reqwest::Client::new());
        let beacon_url_head_event =
            format!("{}eth/v1/events?topics=head", self.beacon_client.endpoint.as_str());

        info!("Starts to subscribe to {}", beacon_url_head_event);
        let mut stream: mev_share_sse::client::EventStream<HeadEvent> =
            client.subscribe(&beacon_url_head_event).await?;

        while let Some(event) = stream.try_next().await? {
            debug!("Received event: {:?}", event);
            let slot = event.slot;
            let epoch = slot / EPOCH_SLOTS;
            let current_epoch = self.network_state.get_current_epoch();
            info!(
                "Received event: current: {}, epoch: {}, epoch_transition: {}",
                current_epoch, epoch, event.epoch_transition
            );
            assert!((epoch != current_epoch) == event.epoch_transition, "Invalid epoch");
            if epoch != current_epoch {
                info!("Epoch changed from {} to {}", current_epoch, epoch);
                self.add_slot(epoch).await?;
            }
            self.network_state.update_slot(slot);
            info!("Current slot: {}", slot);
        }
        Ok(())
    }
}

pub async fn run_cl_process(
    beacon_url: String,
    network_state: NetworkState,
    bls_pk: PublicKey,
    relay_urls: Vec<Url>,
) -> eyre::Result<()> {
    let mut lookahead_fetcher =
        LookaheadFetcher::new(beacon_url, network_state, bls_pk, relay_urls);
    lookahead_fetcher.initialze().await?;
    lookahead_fetcher.run().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bls_public_key_conversion() {
        let pk = PublicKey::default();
        let bls_pk = BlsPublicKey::try_from(pk.to_bytes().as_ref()).unwrap();
        assert_eq!(pk.to_bytes().as_ref(), bls_pk.as_ref());
    }
}
