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
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

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
    constraints: Arc<RwLock<HashMap<u64, ConstraintsData>>>,
    seen_hashes: Arc<RwLock<HashMap<u64, Instant>>>,
}

impl ConstraintsCache {
    /// Insert if not already seen
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
    pub fn spawn_cleanup_task(&self, cancel_token: CancellationToken) -> JoinHandle<()> {
        let seen = self.seen_hashes.clone();
        tokio::spawn(async move {
            let interval = Duration::from_secs(EPOCH_DURATION_SECS * 2); // 64 slots

            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {
                        let now = Instant::now();
                        seen.write().retain(|_, &mut ts| now.duration_since(ts) <= interval);
                    }
                    _ = cancel_token.cancelled() => {
                        info!("Stopping constraint cache cleanup task");
                        break;
                    }
                }
            }
        })
    }
}

pub async fn subscribe_to_constraints_stream(
    constraints_cache: Arc<ConstraintsCache>,
    relays: Vec<RelayClient>,
    cancel_token: CancellationToken,
) -> Result<Vec<JoinHandle<()>>> {
    let mut handles = Vec::new();

    for relay in relays {
        let cache = constraints_cache.clone();
        let cancel_token = cancel_token.clone();

        let handle = tokio::spawn(async move {
            let relay_url = relay.get_url("/").expect("Failed to get relay URL");
            info!("Starting relay subscription for: {}", relay_url);

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        info!("Relay subscription for {} cancelled", relay_url);
                        break;
                    }
                    _ = async {
                        let request = match relay.constraint_stream_request() {
                            Ok(req) => req,
                            Err(err) => {
                                error!("Failed to build constraint stream request for {}: {:?}", relay_url, err);
                                return;
                            }
                        };

                        let mut event_source = match EventSource::new(request) {
                            Ok(src) => src,
                            Err(err) => {
                                error!("Failed to connect to SSE source for {}: {:?}", relay_url, err);
                                return;
                            }
                        };

                        while let Some(event_result) = event_source.next().await {
                            if cancel_token.is_cancelled() {
                                info!("Cancellation detected during event processing for {}", relay_url);
                                return;
                            }

                            match event_result {
                                Ok(Event::Message(message)) => {
                                    if message.event == "signed_constraint" {
                                        let received_constraints =
                                            match serde_json::from_str::<Vec<SignedConstraints>>(
                                                &message.data,
                                            ) {
                                                Ok(constraints) => constraints,
                                                Err(err) => {
                                                    error!("Deserialization error for {}: {:?}", relay_url, err);
                                                    continue;
                                                }
                                            };

                                        debug!("Received {} constraints from {}", received_constraints.len(), relay_url);

                                        for signed_constraint in received_constraints {
                                            match cache.insert(signed_constraint.message) {
                                                Ok(_) => debug!("Inserted constraints from {}", relay_url),
                                                Err(ConstraintCacheError::Duplicate) => {
                                                    debug!("Skipping duplicate constraints from {}", relay_url)
                                                }
                                                Err(err) => {
                                                    error!("Failed to insert constraints from {}: {:?}", relay_url, err)
                                                }
                                            }
                                        }
                                    }
                                }
                                Ok(Event::Open) => {
                                    debug!("SSE stream open for {}", relay_url)
                                }
                                Err(err) => {
                                    warn!("SSE stream error for {}: {:?}", relay_url, err);
                                    break;
                                }
                            }
                        }

                        warn!("SSE stream ended for {}. Reconnecting instantly", relay_url);
                    } => {}
                }
            }
        });

        handles.push(handle);
    }

    Ok(handles)
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
