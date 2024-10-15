use std::sync::Arc;

use beacon_api_client::{mainnet::Client, PayloadAttributesTopic, ProposerDuty};
use eyre::Result;
use futures_util::StreamExt;
use reqwest::Url;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, info};

const SLOT_PER_EPOCH: u64 = 32;

#[derive(Clone)]
pub struct BeaconEventClient {
    bn_client: Arc<Client>,
    duties_tx: UnboundedSender<Vec<ProposerDuty>>,
}

impl BeaconEventClient {
    pub fn new(beacon_node: &str, duties_tx: UnboundedSender<Vec<ProposerDuty>>) -> Self {
        let bn_client =
            Arc::new(Client::new(Url::parse(beacon_node).expect("fail to parse beacon node url")));
        BeaconEventClient { bn_client, duties_tx }
    }

    pub async fn run(&self) -> Result<()> {
        let mut last_updated_slot = 0;
        let mut last_epoch = 0;
        let mut payload_attributes_events = self
            .bn_client
            .get_events::<PayloadAttributesTopic>()
            .await
            .expect("fail to get payload attributes events");

        while let Some(event) = payload_attributes_events.next().await {
            match event {
                Ok(event) => {
                    let new_slot = event.data.proposal_slot;
                    if new_slot > last_updated_slot {
                        let current_epoch = new_slot / SLOT_PER_EPOCH;
                        debug!("Received new slot: {new_slot}, current_eopch: {current_epoch}, last_epoch: {last_epoch}");
                        // We found that helix is slower to sync proposer duties, so we fetch and send duties for the next epoch, when we are near the end of the current epoch
                        if new_slot >= current_epoch * SLOT_PER_EPOCH + SLOT_PER_EPOCH - 1 {
                            let sending_epoch = current_epoch + 1;
                            if sending_epoch != last_epoch {
                                info!("Sending duties for next epoch: {sending_epoch}, last sent epoch: {last_epoch}");
                                last_epoch = sending_epoch;
                                if let Err(e) = self.fetch_and_send_duties(sending_epoch).await {
                                    error!("Failed to fetch and send duties: {e}");
                                }
                            }
                        }
                        last_updated_slot = new_slot;
                    }
                }
                Err(e) => {
                    error!("Failed to get event: {e}");
                }
            }
        }
        Ok(())
    }

    async fn fetch_and_send_duties(&self, epoch: u64) -> Result<()> {
        let (_, all_duties) = self.bn_client.get_proposer_duties(epoch).await?;
        if let Err(e) = self.duties_tx.send(all_duties) {
            error!("Failed to send duties: {e}");
        }
        Ok(())
    }
}
