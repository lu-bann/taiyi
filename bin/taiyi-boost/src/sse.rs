use std::sync::Arc;

use beacon_api_client::{mainnet::Client, PayloadAttributesTopic, ProposerDuty};
use eyre::Result;
use futures_util::StreamExt;
use reqwest::Url;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, info};

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
                        info!("Received new slot: {new_slot}");

                        let current_epoch = new_slot / SLOT_PER_EPOCH;
                        if current_epoch != last_epoch {
                            info!(
                                "Epoch changed to: {current_epoch} from last epoch: {last_epoch}"
                            );
                            last_epoch = current_epoch;
                            // We fetch duties for the next epoch ie: `current_epoch + 1`
                            if let Err(e) = self.fetch_and_send_duties(current_epoch + 1).await {
                                error!("Failed to fetch and send duties: {e}");
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
