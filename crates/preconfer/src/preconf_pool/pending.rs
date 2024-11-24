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

#[cfg(test)]
mod tests {
    use alloy_consensus::TxEnvelope;
    use alloy_eips::eip2718::Decodable2718;
    use alloy_network::TransactionBuilder;
    use alloy_rpc_types::TransactionRequest;
    use taiyi_primitives::BlockspaceAllocation;

    use super::*;

    #[test]
    fn test_add_remove_request() {
        let mut pending = Pending::new();

        let raw_tx = alloy_primitives::hex::decode("02f86f0102843b9aca0085029e7822d68298f094d9e1459a7a482635700cbc20bbaf52d495ab9c9680841b55ba3ac080a0c199674fcb29f353693dd779c017823b954b3c69dffa3cd6b2a6ff7888798039a028ca912de909e7e6cdef9cdcaf24c54dd8c1032946dfa1d85c206b32a9064fe8").unwrap();
        let transaction = TxEnvelope::decode_2718(&mut raw_tx.as_slice()).unwrap();
        let preconf = PreconfRequest {
            allocation: BlockspaceAllocation::default(),
            transaction: Some(transaction),
            target_slot: 1,
        };

        let id = Uuid::new_v4();
        pending.insert(id, preconf.clone());
        assert!(pending.contains(id));
        assert_eq!(pending.by_id.get(&id), Some(&preconf));
        assert_eq!(pending.reqs_by_slot.get(&1), Some(&vec![id]));

        let preconfs = pending.remove_preconfs_for_slot(1).unwrap();
        assert_eq!(preconfs.get(&id), Some(&preconf));
        assert_eq!(pending.by_id.get(&id), None);
        assert_eq!(pending.reqs_by_slot.get(&1), None);
    }

    #[test]
    fn test_remove_preconfs_for_slot_not_found() {
        let mut pending = Pending::new();
        let result = pending.remove_preconfs_for_slot(1);
        assert!(matches!(result, Err(PoolError::SlotNotFound(1))));
    }
}
