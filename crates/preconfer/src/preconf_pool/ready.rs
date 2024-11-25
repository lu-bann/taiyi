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

#[cfg(test)]
mod tests {
    use alloy_consensus::TxEnvelope;
    use alloy_eips::eip2718::Decodable2718;
    use taiyi_primitives::{BlockspaceAllocation, PreconfRequest};
    use uuid::Uuid;

    use super::Ready;

    #[test]
    fn test_add_request() {
        let mut ready = Ready::new(1);
        let raw_tx = alloy_primitives::hex::decode("02f86f0102843b9aca0085029e7822d68298f094d9e1459a7a482635700cbc20bbaf52d495ab9c9680841b55ba3ac080a0c199674fcb29f353693dd779c017823b954b3c69dffa3cd6b2a6ff7888798039a028ca912de909e7e6cdef9cdcaf24c54dd8c1032946dfa1d85c206b32a9064fe8").unwrap();
        let transaction = TxEnvelope::decode_2718(&mut raw_tx.as_slice()).unwrap();
        let preconf = PreconfRequest {
            allocation: BlockspaceAllocation::default(),
            transaction: Some(transaction),
            target_slot: 1,
        };

        let id = Uuid::new_v4();
        ready.insert_order(id, preconf.clone());
        assert!(ready.contains(id));

        let preconfs = ready.fetch_preconf_requests().unwrap();
        assert_eq!(preconfs.len(), 1);
        assert_eq!(preconfs[0], preconf);
    }
}
