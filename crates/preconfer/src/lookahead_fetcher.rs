use std::future::Future;

use alloy_eips::merge::EPOCH_SLOTS;
use alloy_rpc_types_beacon::events::HeadEvent;
use beacon_api_client::{mainnet::Client, BlockId};
use blst::min_pk::PublicKey;
use ethereum_consensus::primitives::BlsPublicKey;
use futures::TryStreamExt;
use mev_share_sse::EventClient;
use reqwest::Url;
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
        beacon_rpc_url: String,
        network_state: NetworkState,
        gateway_pubkey: PublicKey,
        relay_urls: Vec<Url>,
    ) -> Self {
        let gateway_pubkey =
            BlsPublicKey::try_from(gateway_pubkey.to_bytes().as_ref()).expect("Invalid public key");
        Self {
            beacon_client: Client::new(Url::parse(&beacon_rpc_url).expect("Invalid URL")),
            network_state,
            gateway_pubkey,
            relay_client: RelayClient::new(relay_urls),
        }
    }

    pub async fn initialze(&mut self) -> eyre::Result<()> {
        let head = self.beacon_client.get_beacon_block(BlockId::Head).await?;
        let slot = head.message().slot();
        let epoch = slot / self.network_state.context.slots_per_epoch;

        // Fetch gateway delegations for the current epoch
        self.get_delegation_for_current_epoch(epoch, slot).await?;
        // Fetch gateway delegations for the next epoch
        self.get_delegation_for(epoch + 1).await?;
        self.network_state.update_slot(slot);

        // Update the fee recipients for the current epoch
        let fee_recipients = self.relay_client.get_current_epoch_validators().await?;
        self.network_state.update_fee_recipients(fee_recipients);
        Ok(())
    }

    /// Fetch delegation for slots from the present epoch
    /// Note: Only called once on initialization
    async fn get_delegation_for_current_epoch(
        &mut self,
        epoch: u64,
        head_slot: u64,
    ) -> eyre::Result<()> {
        // Fetch delegations for remaining slots in the given epoch
        for slot in head_slot + 1..((epoch + 1) * self.network_state.context.slots_per_epoch) {
            let res = self.relay_client.get_delegations(slot).await;
            match res {
                Ok(signed_delegations) => {
                    'delegation_loop: for signed_delegation in signed_delegations {
                        let delegation_message = signed_delegation.message;
                        if delegation_message.action == DELEGATION_ACTION
                            && delegation_message.delegatee_pubkey == self.gateway_pubkey
                        {
                            info!("Delegation to gateway found for slot: {}", slot);
                            self.network_state.add_slot(slot);
                            break 'delegation_loop;
                        }
                    }
                }
                Err(e) => {
                    // when there is no delegations for the slot, relay would return error
                    debug!("Could not fetch delegations for slot: {}, error: {}", slot, e);
                }
            }
        }

        Ok(())
    }

    /// Fetch delegation for slots from the epoch
    async fn get_delegation_for(&mut self, epoch: u64) -> eyre::Result<()> {
        // Fetch delegations for every slot in the given epoch
        for slot in (epoch * self.network_state.context.slots_per_epoch)
            ..((epoch + 1) * self.network_state.context.slots_per_epoch)
        {
            let res = self.relay_client.get_delegations(slot).await;
            match res {
                Ok(signed_delegations) => {
                    'delegation_loop: for signed_delegation in signed_delegations {
                        let delegation_message = signed_delegation.message;
                        if delegation_message.action == DELEGATION_ACTION
                            && delegation_message.delegatee_pubkey == self.gateway_pubkey
                        {
                            info!("Delegation to gateway found for slot: {}", slot);
                            self.network_state.add_slot(slot);
                            break 'delegation_loop;
                        }
                    }
                }
                Err(e) => {
                    // when there is no delegations for the slot, relay would return error
                    debug!("Could not fetch delegations for slot: {}, error: {}", slot, e);
                }
            }
        }

        Ok(())
    }

    pub async fn run(mut self) -> eyre::Result<()> {
        info!("Initializing lookahead fetcher");
        self.initialze().await?;
        let client = EventClient::new(reqwest::Client::new());
        let beacon_url_head_event =
            format!("{}eth/v1/events?topics=head", self.beacon_client.endpoint.as_str());

        info!("Starts to subscribe to {}", beacon_url_head_event);
        let mut stream: mev_share_sse::client::EventStream<HeadEvent> =
            client.subscribe(&beacon_url_head_event).await?;

        while let Some(event) = stream.try_next().await? {
            info!(
                head_slot = event.slot,
                epoch = event.slot / EPOCH_SLOTS,
                epoch_transition = event.epoch_transition,
            );
            let new_slot = event.slot;
            if event.epoch_transition {
                let new_epoch = new_slot / EPOCH_SLOTS;
                let past_epoch = self.network_state.get_current_epoch();
                info!("Epoch transition occured, current: {new_epoch} previous: {past_epoch}");
                self.get_delegation_for(new_epoch + 1).await?;

                // Update the fee recipients for the new epoch
                let fee_recipients = self.relay_client.get_current_epoch_validators().await?;
                self.network_state.update_fee_recipients(fee_recipients);
            }
            self.network_state.update_slot(new_slot);
        }
        Ok(())
    }
}

pub async fn run_cl_process(
    beacon_rpc_url: String,
    network_state: NetworkState,
    bls_pk: PublicKey,
    relay_urls: Vec<Url>,
) -> impl Future<Output = eyre::Result<()>> {
    let lookahead_fetcher =
        LookaheadFetcher::new(beacon_rpc_url, network_state, bls_pk, relay_urls);
    lookahead_fetcher.run()
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
