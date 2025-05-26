use std::sync::Arc;

use cb_common::pbs::RelayClient;
use eyre::Result;
use futures::StreamExt;
use parking_lot::RwLock;
use reqwest_eventsource::{Event, EventSource};
use scc::HashMap;
use tracing::{error, info};

use crate::{
    ext::relay::RelayExt,
    types::{ConstraintsData, ConstraintsMessage, SignedConstraints},
};

#[derive(Clone, Default, Debug)]
pub struct ConstraintsCache {
    pub constraints: Arc<RwLock<HashMap<u64, ConstraintsData>>>,
}

impl ConstraintsCache {
    pub fn insert(&self, messgae: ConstraintsMessage) -> Result<()> {
        let constraints_data = ConstraintsData::try_from(messgae.clone())?;
        self.constraints
            .write()
            .insert(messgae.slot, constraints_data)
            .map_err(|_| eyre::eyre!("Failed to insert"))?;
        Ok(())
    }

    // remove all constraints for the given slot.
    pub fn remove(&self, slot: u64) -> Option<(u64, ConstraintsData)> {
        self.constraints.write().remove(&slot)
    }

    // Get total constraints for the given slot.
    pub fn get(&self, slot: u64) -> Option<ConstraintsData> {
        self.constraints.read().get(&slot).map(|x| x.get().clone())
    }
}

pub async fn subscribe_to_constraints_stream(
    constraints_cache: ConstraintsCache,
    relays: &[RelayClient],
) -> eyre::Result<()> {
    info!("Starting constraint subscriber");
    let request =
        relays.first().expect("Atleast one relay configured").constraint_stream_request()?;
    let event_source = EventSource::new(request).unwrap_or_else(|err| {
        panic!("Failed to create EventSource: {:?}", err);
    });

    tokio::spawn(async move {
        let mut event_source = event_source;
        while let Some(event) = event_source.next().await {
            match event {
                Ok(Event::Message(message)) => {
                    if message.event == "signed_constraint" {
                        let data = &message.data;
                        let received_constraints =
                            serde_json::from_str::<Vec<SignedConstraints>>(data)
                                .expect("at least one constraint");

                        info!("Received constraints: {:?}", received_constraints);

                        // Insert the constraints into the cache
                        for signed_constraint in received_constraints.into_iter() {
                            if let Err(err) = constraints_cache.insert(signed_constraint.message) {
                                error!("Failed to insert constraints into cache: {:?}", err);
                            }
                        }
                    }
                }
                Ok(Event::Open) => {
                    info!("SSE connection opened");
                }
                Err(err) => {
                    error!("Error receiving SSE event: {:?}", err);
                }
            }
        }

        info!("Stopping constraint subscriber");
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy_eips::eip2718::Encodable2718;
    use alloy_network::{EthereumWallet, TransactionBuilder};
    use alloy_primitives::{Address, Bytes};
    use alloy_rpc_types_beacon::BlsPublicKey;
    use alloy_signer::k256::ecdsa::SigningKey;
    use alloy_signer_local::PrivateKeySigner;

    use super::*;
    use crate::utils::tests::gen_test_tx_request;

    #[tokio::test]
    async fn test_constraints_cache() -> eyre::Result<()> {
        let raw_sk = "0x84286521b97e7c10916857c307553e30a9defd100e893e96fc8aad42336a4ab3";
        let hex_sk = raw_sk.strip_prefix("0x").unwrap_or(raw_sk);

        let sk = SigningKey::from_slice(hex::decode(hex_sk)?.as_slice())?;
        let signer = PrivateKeySigner::from_signing_key(sk.clone());
        let wallet = EthereumWallet::from(signer);
        let sender = Address::from_private_key(&sk);
        let tx = gen_test_tx_request(sender, 1, Some(1));
        let tx_signed = tx.build(&wallet).await?;
        let raw_encoded = tx_signed.encoded_2718();
        let tx_bytes: Bytes = Bytes::from(raw_encoded.as_slice().to_vec());
        let cache = ConstraintsCache::default();
        let txs = vec![tx_bytes];
        let constraints = ConstraintsMessage {
            pubkey: BlsPublicKey::default(),
            slot: 1,
            top: false,
            transactions: txs,
        };
        cache.insert(constraints.clone()).ok();
        assert_eq!(cache.get(1).unwrap().transactions.len(), 1);
        Ok(())
    }
}
