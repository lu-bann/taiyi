#![allow(unused)]
use std::collections::HashSet;

use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Decodable2718;
use ethereum_consensus::{
    deneb::{mainnet::MAX_BYTES_PER_TRANSACTION, Transaction},
    primitives::{BlsPublicKey, BlsSignature},
    ssz::prelude::*,
};
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
        self.constraints.insert(constraints.slot, txs);
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
    use super::*;

    #[test]
    fn test_constraints_cache() {
        let cache = ConstraintsCache::new();
        let dup_txs = vec![Transaction::default(), Transaction::default()];
        let constraints = ConstraintsMessage { slot: 1, tx: dup_txs.clone() };
        cache.insert(constraints.clone());
        let unique_txs = vec![Transaction::default()];
        assert_eq!(cache.get(1), Some(unique_txs.clone()));
        cache.prune(1);
        assert_eq!(cache.get(1), Some(unique_txs));
        cache.prune(2);
        assert_eq!(cache.get(1), None);
    }
}
