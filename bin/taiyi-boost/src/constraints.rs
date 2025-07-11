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
    pub fn insert(&self, message: ConstraintsMessage) -> Result<()> {
        let constraints_data = ConstraintsData::try_from(message.clone())?;
        self.constraints
            .write()
            .insert(message.slot, constraints_data)
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

    let relay = relays.first().expect("At least one relay must be configured").clone();

    loop {
        match relay.constraint_stream_request() {
            Ok(request) => {
                let mut event_source = EventSource::new(request)?;
                while let Some(Ok(Event::Message(message))) = event_source.next().await {
                    if message.event == "signed_constraint" {
                        let received_constraints: Vec<SignedConstraints> =
                            serde_json::from_str(&message.data)?;
                        for constraint in received_constraints {
                            constraints_cache.insert(constraint.message)?;
                        }
                    }
                }
            }
            Err(err) => {
                error!("Failed to connect to SSE source: {:?}", err);
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use alloy::eips::eip2718::Encodable2718;
    use alloy::network::{EthereumWallet, TransactionBuilder};
    use alloy::primitives::{Address, Bytes, U256};
    use alloy::rpc::types::beacon::BlsPublicKey;
    use alloy::rpc::types::eth::TransactionRequest;
    use alloy::signers::k256::ecdsa::SigningKey;
    use alloy::signers::local::PrivateKeySigner;

    use super::*;

    pub fn gen_test_tx_request(
        sender: Address,
        chain_id: u64,
        nonce: Option<u64>,
    ) -> TransactionRequest {
        TransactionRequest::default()
            .with_from(sender)
            // Burn it
            .with_to(Address::ZERO)
            .with_chain_id(chain_id)
            .with_nonce(nonce.unwrap_or(0))
            .with_value(U256::from(100))
            .with_gas_limit(21_000)
            .with_max_priority_fee_per_gas(1_000_000_000) // 1 gwei
            .with_max_fee_per_gas(20_000_000_000)
    }

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
