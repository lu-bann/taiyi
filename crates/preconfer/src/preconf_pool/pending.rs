use std::collections::HashMap;

use eyre::Result;
use taiyi_primitives::PreconfRequest;
use uuid::Uuid;

use crate::error::PoolError;

/// A pool of transactions that are currently waiting for their target slot to be reached.
#[derive(Debug, Clone)]

pub struct Pending {
    by_id: HashMap<Uuid, PreconfRequest>,
    reqs_by_slot: HashMap<u64, Vec<Uuid>>,
}

impl Pending {
    pub fn new() -> Self {
        Self { by_id: HashMap::new(), reqs_by_slot: HashMap::new() }
    }

    pub fn insert(&mut self, request_id: Uuid, preconf_request: PreconfRequest) {
        let slot = preconf_request.target_slot;
        self.by_id.insert(request_id, preconf_request);
        self.reqs_by_slot.entry(slot).or_default().push(request_id);
    }

    pub fn contains(&self, key: Uuid) -> bool {
        self.by_id.contains_key(&key)
    }

    pub fn remove_preconfs_for_slot(
        &mut self,
        slot: u64,
    ) -> Result<HashMap<Uuid, PreconfRequest>, PoolError> {
        if let Some(reqs) = self.reqs_by_slot.remove(&slot) {
            let mut preconfs = HashMap::new();
            for req_id in reqs {
                let preconf_request = match self.by_id.remove(&req_id) {
                    Some(req) => req,
                    None => return Err(PoolError::PreconfRequestNotFound(req_id)),
                };
                preconfs.insert(req_id, preconf_request);
            }
            Ok(preconfs)
        } else {
            Err(PoolError::SlotNotFound(slot))
        }
    }
}
