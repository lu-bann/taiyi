use std::collections::HashMap;

use alloy_primitives::{Address, U256};
use taiyi_primitives::PreconfRequest;
use uuid::Uuid;

/// Stores all preconf request without preconf transactions
#[derive(Debug, Clone)]
pub struct Pending {
    by_id: HashMap<Uuid, PreconfRequest>,
    by_account: HashMap<Address, Vec<Uuid>>,
    reqs_by_slot: HashMap<u64, Vec<Uuid>>,
}

impl Pending {
    pub fn new() -> Self {
        Self { by_id: HashMap::new(), by_account: HashMap::new(), reqs_by_slot: HashMap::new() }
    }

    pub fn get(&self, key: Uuid) -> Option<PreconfRequest> {
        self.by_id.get(&key).cloned()
    }

    pub fn contains(&self, key: Uuid) -> bool {
        self.by_id.contains_key(&key)
    }

    pub fn insert(&mut self, key: Uuid, value: PreconfRequest) {
        self.by_id.insert(key, value.clone());
        self.by_account.entry(value.signer().expect("signer")).or_default().push(key);
        self.reqs_by_slot.entry(value.target_slot()).or_default().push(key);
    }

    pub fn remove(&mut self, key: Uuid) -> Option<PreconfRequest> {
        if let Some(preconf) = self.by_id.get(&key) {
            if let Some(account) = preconf.signer() {
                if let Some(ids) = self.by_account.get_mut(&account) {
                    ids.retain(|id| *id != key);
                    if ids.is_empty() {
                        self.by_account.remove(&account);
                    }
                }
            }
        }
        self.by_id.remove(&key)
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

    /// Fetches all preconf requests for a given slot.
    /// This is used to fetch all preconf requests which hasn't received a preconf transaction yet.
    pub fn fetch_preconf_requests_for_slot(&self, slot: u64) -> Option<Vec<PreconfRequest>> {
        self.reqs_by_slot
            .get(&slot)
            .map(|ids| ids.iter().filter_map(|id| self.by_id.get(id)).cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, U256, PrimitiveSignature};
    use taiyi_primitives::{BlockspaceAllocation, PreconfRequest};
    use uuid::Uuid;

    use super::Pending;

    #[test]
    fn test_add_remove_request() {
        let mut parked = Pending::new();
        let request = PreconfRequest {
            allocation: BlockspaceAllocation::default(),
            alloc_sig: PrimitiveSignature::new(U256::ZERO, U256::ZERO, false),
            transaction: None,
            signer: Some(Address::default()),
        };

        let id = Uuid::new_v4();
        parked.insert(id, request.clone());
        assert!(parked.contains(id));
        assert_eq!(parked.get(id), Some(request.clone()));

        parked.remove(id);
        assert_eq!(parked.get(id), None);
    }

    #[test]
    fn test_get_pending_diffs_for_account_after_insert_multiple_and_remove() {
        let mut parked = Pending::new();
        let account = Address::default();

        let request1 = PreconfRequest {
            allocation: BlockspaceAllocation { deposit: U256::from(100), ..Default::default() },
            alloc_sig: PrimitiveSignature::new(U256::ZERO, U256::ZERO, false),
            transaction: None,
            signer: Some(account),
        };
        let request2 = PreconfRequest {
            allocation: BlockspaceAllocation { deposit: U256::from(200), ..Default::default() },
            alloc_sig: PrimitiveSignature::new(U256::ZERO, U256::ZERO, false),
            transaction: None,
            signer: Some(account),
        };

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        parked.insert(id1, request1.clone());
        parked.insert(id2, request2.clone());

        assert_eq!(parked.get_pending_diffs_for_account(account), Some(U256::from(300)));

        parked.remove(id1);
        assert_eq!(parked.get_pending_diffs_for_account(account), Some(U256::from(200)));

        parked.remove(id2);
        assert_eq!(parked.get_pending_diffs_for_account(account), None);
    }
}
