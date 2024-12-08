use std::collections::HashSet;

use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Decodable2718;
use eyre::Result;
use scc::HashMap;

use crate::types::ConstraintsMessage;

#[derive(Clone, Default, Debug)]
pub struct ConstraintsCache {
    pub constraints: HashMap<u64, Vec<TxEnvelope>>,
}

impl ConstraintsCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn remove_duplicate(&self, constraints: ConstraintsMessage) -> ConstraintsMessage {
        let mut seen = HashSet::new();
        let mut unique = Vec::new();

        for tx in constraints.transactions.clone() {
            if seen.insert(tx.to_string()) {
                unique.push(tx);
            }
        }
        let mut constraints = constraints.clone();
        constraints.transactions = unique;
        constraints
    }

    pub fn insert(&self, constraints: ConstraintsMessage) -> Result<()> {
        let constraints = self.remove_duplicate(constraints);
        let txs: Vec<TxEnvelope> = constraints
            .transactions
            .iter()
            .map(|bytes| TxEnvelope::decode_2718(&mut bytes.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        self.constraints
            .insert(constraints.slot, txs)
            .map_err(|_| eyre::eyre!("Failed to insert"))?;
        Ok(())
    }

    // remove all constraints before the given slot.
    pub fn prune(&self, slot: u64) {
        self.constraints.retain(|&k, _| k >= slot);
    }

    // Get total constraints for the given slot.
    pub fn get(&self, slot: u64) -> Option<Vec<TxEnvelope>> {
        self.constraints.get(&slot).map(|x| x.get().clone())
    }
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
        let hex_sk = raw_sk.strip_prefix("0x").unwrap_or(&raw_sk);

        let sk = SigningKey::from_slice(hex::decode(hex_sk)?.as_slice())?;
        let signer = PrivateKeySigner::from_signing_key(sk.clone());
        let wallet = EthereumWallet::from(signer);
        let sender = Address::from_private_key(&sk);
        let tx = gen_test_tx_request(sender, 1, Some(1));
        let tx_signed = tx.build(&wallet).await?;
        let raw_encoded = tx_signed.encoded_2718();
        let tx_bytes: Bytes = Bytes::from(raw_encoded.as_slice().to_vec());
        let cache = ConstraintsCache::new();
        let dup_txs = vec![tx_bytes.clone(), tx_bytes];
        let constraints = ConstraintsMessage {
            pubkey: BlsPublicKey::default(),
            slot: 1,
            top: false,
            transactions: dup_txs,
        };
        cache.insert(constraints.clone()).ok();
        assert_eq!(cache.get(1).unwrap().len(), 1);
        cache.prune(1);
        assert_eq!(cache.get(1).unwrap().len(), 1);
        cache.prune(2);
        assert_eq!(cache.get(1), None);
        Ok(())
    }
}
