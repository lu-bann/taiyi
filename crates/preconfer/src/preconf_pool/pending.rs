use std::collections::HashMap;

use eyre::Result;
use taiyi_primitives::{PreconfHash, PreconfRequest};

use crate::error::PoolError;

/// A pool of transactions that are currently waiting for their target slot to be reached.
#[derive(Debug, Clone)]

pub struct Pending {
    by_hash: HashMap<PreconfHash, PreconfRequest>,
    reqs_by_slot: HashMap<u64, Vec<PreconfHash>>,
}

impl Pending {
    pub fn new() -> Self {
        Self { by_hash: HashMap::new(), reqs_by_slot: HashMap::new() }
    }

    pub fn insert(&mut self, preconf_hash: PreconfHash, preconf_request: PreconfRequest) {
        let slot = preconf_request.target_slot().to();
        self.by_hash.insert(preconf_hash, preconf_request);
        self.reqs_by_slot.entry(slot).or_default().push(preconf_hash);
    }

    pub fn contains(&self, key: &PreconfHash) -> bool {
        self.by_hash.contains_key(key)
    }

    #[allow(dead_code)]
    pub fn remove_preconfs_for_slot(
        &mut self,
        slot: u64,
    ) -> Result<HashMap<PreconfHash, PreconfRequest>, PoolError> {
        if let Some(reqs) = self.reqs_by_slot.remove(&slot) {
            let mut preconfs = HashMap::new();
            for preconf_hash in reqs {
                let preconf_request = match self.by_hash.remove(&preconf_hash) {
                    Some(req) => req,
                    None => return Err(PoolError::PreconfRequestNotFound(preconf_hash)),
                };
                preconfs.insert(preconf_hash, preconf_request);
            }
            Ok(preconfs)
        } else {
            Err(PoolError::SlotNotFound(slot))
        }
    }
}
