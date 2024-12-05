#![allow(unused)]
use std::collections::HashSet;

use ethereum_consensus::deneb::{mainnet::MAX_BYTES_PER_TRANSACTION, Transaction};
use scc::HashMap;

#[derive(Clone, Default, Debug)]
pub struct ConstraintsMessage {
    pub slot: u64,
    pub tx: Vec<Transaction<MAX_BYTES_PER_TRANSACTION>>,
}

#[derive(Clone, Default, Debug)]
pub struct ConstraintsCache {
    pub constraints: HashMap<u64, Vec<Transaction<MAX_BYTES_PER_TRANSACTION>>>,
}

impl ConstraintsCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn remove_duplicate(&self, constraints: ConstraintsMessage) -> ConstraintsMessage {
        let mut seen = HashSet::new();
        let mut unique = Vec::new();

        for tx in constraints.tx {
            if seen.insert(tx.to_string()) {
                unique.push(tx);
            }
        }

        ConstraintsMessage { slot: constraints.slot, tx: unique }
    }

    pub fn insert(&self, constraints: ConstraintsMessage) {
        let constraints = self.remove_duplicate(constraints);
        self.constraints.insert(constraints.slot, constraints.tx);
    }

    // remove all constraints before the given slot.
    pub fn prune(&self, slot: u64) {
        self.constraints.retain(|&k, _| k >= slot);
    }

    // Get total constraints for the given slot.
    pub fn get(&self, slot: u64) -> Option<Vec<Transaction<MAX_BYTES_PER_TRANSACTION>>> {
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
