use std::sync::Arc;

use beacon_api_client::{mainnet::Client, PayloadAttributesTopic, ProposerDuty};
use eyre::Result;
use futures_util::StreamExt;
use reqwest::Url;
use tokio::sync::mpsc::UnboundedSender;
use tracing::error;

const EPOCH_SLOTS: u64 = 32;
const PROPOSER_DUTIES_REFRESH_FREQ: u64 = EPOCH_SLOTS / 4;

#[derive(Clone)]
pub struct BeaconEventClient {
    bn_client: Arc<Client>,
    duties_tx: UnboundedSender<Vec<ProposerDuty>>,
}

impl BeaconEventClient {
    pub fn new(beacon_node: &str, duties_tx: UnboundedSender<Vec<ProposerDuty>>) -> Self {
        let bn_client =
            Client::new(Url::parse(beacon_node).expect("fail to parse beacon node url"));
        BeaconEventClient { bn_client: Arc::new(bn_client), duties_tx }
    }
    pub async fn run(&self) -> Result<()> {
        let mut last_updated_slot = 0;
        let mut payload_attributes_events = self
            .bn_client
            .clone()
            .get_events::<PayloadAttributesTopic>()
            .await
            .expect("fail to get payload attributes events");
        while let Some(event) = payload_attributes_events.next().await {
            match event {
                Ok(event) => {
                    let new_slot = event.data.proposal_slot;
                    if last_updated_slot == 0
                        || (new_slot > last_updated_slot
                            && new_slot % PROPOSER_DUTIES_REFRESH_FREQ == 0)
                    {
                        last_updated_slot = new_slot;
                        if let Err(e) = self.fetch_and_send_duties(new_slot).await {
                            error!("Failed to fetch and send duties: {e}");
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to get event: {e}");
                }
            }
        }
        Ok(())
    }
    // Fetch for `epoch` and `epoch + 1`;
    async fn fetch_and_send_duties(&self, slot: u64) -> Result<()> {
        let epoch = slot / EPOCH_SLOTS;
        let mut all_duties = Vec::with_capacity(64);
        for i in 0..2 {
            let (_, duties) = self.bn_client.get_proposer_duties(epoch + i).await?;
            all_duties.extend(duties);
        }
        if let Err(e) = self.duties_tx.send(all_duties) {
            error!("Failed to send duties: {e}");
        }
        Ok(())
    }
}
