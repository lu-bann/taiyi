use std::collections::HashMap;

use taiyi_primitives::PreconfRequest;
use uuid::Uuid;

use crate::error::PoolError;

/// Only contains orders for which target slot is next current slot + 1
#[derive(Debug, Clone)]
pub struct Ready {
    requests: HashMap<Uuid, PreconfRequest>,
    // current slot = target_slot - 1
    slot: u64,
}

impl Ready {
    pub fn new(slot: u64) -> Self {
        Self { requests: HashMap::default(), slot }
    }

    pub fn contains(&self, key: Uuid) -> bool {
        self.requests.contains_key(&key)
    }

    pub fn insert_order(&mut self, request_id: Uuid, preconf_request: PreconfRequest) {
        if self.requests.contains_key(&request_id) {
            return;
        }
        self.requests.insert(request_id, preconf_request);
    }

    pub fn fetch_preconf_requests(&mut self) -> Result<Vec<PreconfRequest>, PoolError> {
        let mut preconfs = Vec::new();
        for (_, preconf_request) in self.requests.drain() {
            preconfs.push(preconf_request);
        }
        Ok(preconfs)
    }

    pub fn update_slot(&mut self, slot: u64) {
        self.slot = slot;
    }
}
