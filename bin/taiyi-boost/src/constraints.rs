use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_eips::{eip2718::Eip2718Error, merge::EPOCH_DURATION_SECS};
use cb_common::pbs::RelayClient;
use eyre::Result;
use futures::StreamExt;
use parking_lot::RwLock;
use reqwest_eventsource::{Event, EventSource};
use scc::HashMap;
use thiserror::Error;
use tracing::{debug, error, info};

use crate::{
    ext::relay::RelayExt,
    types::{ConstraintsData, ConstraintsMessage, SignedConstraints},
};

#[derive(Debug, Error)]
pub enum ConstraintCacheError {
    #[error("Constraint already seen")]
    Duplicate,

    #[error("Failed to convert ConstraintsMessage: {0}")]
    Conversion(#[from] Eip2718Error),

    #[error("Internal insert failure: {0}")]
    Internal(String),
}

#[derive(Clone, Default, Debug)]
pub struct ConstraintsCache {
    pub constraints: Arc<RwLock<HashMap<u64, ConstraintsData>>>,
    pub seen_hashes: Arc<RwLock<HashMap<u64, Instant>>>,
}

impl ConstraintsCache {
    /// Creates a new ConstraintsCache and spawns the deduplication cleanup task.
    pub fn new_with_cleanup() -> Self {
        let cache = Self::default();
        cache.spawn_cleanup_task();
        cache
    }

    /// Insert if not already seen. Returns true if inserted.
    pub fn insert(&self, message: ConstraintsMessage) -> Result<(), ConstraintCacheError> {
        let hash = message.hash();
        let now = Instant::now();

        let seen = self.seen_hashes.write();
        if seen.contains(&hash) {
            return Err(ConstraintCacheError::Duplicate);
        }

        let constraints_data =
            ConstraintsData::try_from(message.clone()).map_err(ConstraintCacheError::Conversion)?;

        let constraints = self.constraints.write();
        constraints
            .entry(message.slot)
            .and_modify(|existing| {
                existing.transactions.extend(constraints_data.transactions.iter().cloned());
                existing.proof_data.extend(constraints_data.proof_data.iter().cloned());
            })
            .or_insert(constraints_data);

        seen.insert(hash, now).map_err(|_| {
            ConstraintCacheError::Internal("Failed to insert into seen_hashes".to_string())
        })?;
        Ok(())
    }

    /// remove all constraints for the given slot.
    pub fn remove(&self, slot: u64) -> Option<(u64, ConstraintsData)> {
        self.constraints.write().remove(&slot)
    }

    /// Get total constraints for the given slot.
    pub fn get(&self, slot: u64) -> Option<ConstraintsData> {
        self.constraints.read().get(&slot).map(|x| x.get().clone())
    }

    /// Spawns a background task to periodically clean old entries from `seen_hashes`.
    fn spawn_cleanup_task(&self) {
        let seen = self.seen_hashes.clone();
        tokio::spawn(async move {
            let interval = Duration::from_secs(EPOCH_DURATION_SECS * 2); // 64 slots

            loop {
                let now = Instant::now();
                seen.write().retain(|_, &mut ts| now.duration_since(ts) <= interval);

                tokio::time::sleep(interval).await;
            }
        });
    }
}

pub async fn subscribe_to_constraints_stream(
    constraints_cache: Arc<ConstraintsCache>,
    relays: Vec<RelayClient>,
) -> Result<()> {
    info!("Starting constraint subscriber with {} relay(s)", relays.len());

    for relay in relays {
        let cache = constraints_cache.clone();
        tokio::spawn({
            async move {
                loop {
                    match relay.constraint_stream_request() {
                        Ok(request) => match EventSource::new(request) {
                            Ok(mut event_source) => {
                                while let Some(event_result) = event_source.next().await {
                                    match event_result {
                                        Ok(Event::Message(message)) => {
                                            if message.event == "signed_constraint" {
                                                match serde_json::from_str::<Vec<SignedConstraints>>(
                                                    &message.data,
                                                ) {
                                                    Ok(received_constraints) => {
                                                        debug!(
                                                            "Received constraints: {:?}",
                                                            received_constraints
                                                        );
                                                        for signed_constraint in
                                                            received_constraints
                                                        {
                                                            match cache
                                                                .insert(signed_constraint.message)
                                                            {
                                                                Ok(_) => debug!("Inserted constraints"),
                                                                Err(ConstraintCacheError::Duplicate) =>
                                                                    debug!("Skipping duplicate constraints"),
                                                                Err(err) =>
                                                                    error!(
                                                                        "Failed to insert constraints: {:?}",
                                                                        err
                                                                    ),
                                                            }
                                                        }
                                                    }
                                                    Err(err) => {
                                                        error!("Deserialization error: {:?}", err)
                                                    }
                                                }
                                            }
                                        }
                                        Ok(Event::Open) => debug!("SSE stream open"),
                                        Err(err) => {
                                            error!("SSE stream error: {:?}", err);
                                            break;
                                        }
                                    }
                                }
                                info!("SSE stream ended. Reconnecting instantly");
                            }
                            Err(err) => error!("Failed to connect to SSE source: {:?}", err),
                        },
                        Err(err) => error!("Failed to build constraint stream request: {:?}", err),
                    }
                }
            }
        });
    }

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
