use std::collections::HashMap;

use alloy_primitives::{Address, U256};
use eyre::Result;
use taiyi_primitives::PreconfRequest;
use uuid::Uuid;

use crate::error::PoolError;

/// Stores all preconf request with preconf transactions
#[derive(Debug, Clone)]
pub struct Ready {
    by_id: HashMap<Uuid, PreconfRequest>,
    by_account: HashMap<Address, Vec<Uuid>>,
    reqs_by_slot: HashMap<u64, Vec<Uuid>>,
}

impl Ready {
    pub fn new() -> Self {
        Self { by_id: HashMap::new(), reqs_by_slot: HashMap::new(), by_account: HashMap::new() }
    }

    pub fn insert(&mut self, request_id: Uuid, preconf_request: PreconfRequest) {
        let slot = preconf_request.target_slot();
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
            Err(PoolError::RequestsNotFoundForSlot(slot))
        }
    }

    pub fn fetch_preconf_requests_for_slot(
        &self,
        slot: u64,
    ) -> Result<Vec<PreconfRequest>, PoolError> {
        if let Some(reqs) = self.reqs_by_slot.get(&slot) {
            let mut preconfs = Vec::new();
            for req_id in reqs {
                let preconf_request = match self.by_id.get(req_id) {
                    Some(req) => req.clone(),
                    None => return Err(PoolError::PreconfRequestNotFound(*req_id)),
                };
                preconfs.push(preconf_request);
            }
            Ok(preconfs)
        } else {
            Err(PoolError::RequestsNotFoundForSlot(slot))
        }
    }

    /// Calculates the total pending deposit for all parked transactions.
    /// This is the sum of the deposit of all parked transactions.
    pub fn get_pending_diffs_for_account(&self, account: Address) -> Option<U256> {
        self.by_account.get(&account).map(|ids| {
            ids.iter()
                .filter_map(|id| self.by_id.get(id))
                .map(|preconf| preconf.allocation.deposit)
                .sum()
        })
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::TxEnvelope;
    use alloy_eips::eip2718::Decodable2718;
    use alloy_network::TransactionBuilder;
    use alloy_rpc_types::TransactionRequest;
    use taiyi_primitives::BlockspaceAllocation;
    use alloy_primitives::PrimitiveSignature;

    use super::*;

    #[test]
    fn test_remove_preconfs_for_slot_not_found() {
        let mut ready = Ready::new();
        let result = ready.remove_preconfs_for_slot(1);
        assert!(matches!(result, Err(PoolError::RequestsNotFoundForSlot(1))));
    }

    #[test]
    fn test_add_request() {
        let mut ready = Ready::new();
        let raw_tx = alloy_primitives::hex::decode("02f86f0102843b9aca0085029e7822d68298f094d9e1459a7a482635700cbc20bbaf52d495ab9c9680841b55ba3ac080a0c199674fcb29f353693dd779c017823b954b3c69dffa3cd6b2a6ff7888798039a028ca912de909e7e6cdef9cdcaf24c54dd8c1032946dfa1d85c206b32a9064fe8").unwrap();
        let transaction = TxEnvelope::decode_2718(&mut raw_tx.as_slice()).unwrap();
        let preconf = PreconfRequest {
            allocation: BlockspaceAllocation { target_slot: 1, ..Default::default() },
            alloc_sig: PrimitiveSignature::new(U256::ZERO, U256::ZERO, false),
            transaction: Some(transaction),
            signer: Some(Address::default()),
        };

        let id = Uuid::new_v4();
        ready.insert(id, preconf.clone());
        assert!(ready.contains(id));

        let preconfs = ready.fetch_preconf_requests_for_slot(1).unwrap();
        assert_eq!(preconfs.len(), 1);
        assert_eq!(preconfs[0], preconf);
    }
}
