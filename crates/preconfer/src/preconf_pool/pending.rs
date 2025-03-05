use std::collections::HashMap;

use alloy_primitives::{Address, U256};
use taiyi_primitives::PreconfRequestTypeB;
use uuid::Uuid;

/// Stores all preconf request without preconf transactions
#[derive(Debug, Clone)]
pub struct Pending {
    by_id: HashMap<Uuid, PreconfRequestTypeB>,
    by_account: HashMap<Address, Vec<Uuid>>,
    reqs_by_slot: HashMap<u64, Vec<Uuid>>,
}

impl Pending {
    pub fn new() -> Self {
        Self { by_id: HashMap::new(), by_account: HashMap::new(), reqs_by_slot: HashMap::new() }
    }

    pub fn get(&self, key: Uuid) -> Option<PreconfRequestTypeB> {
        self.by_id.get(&key).cloned()
    }

    #[cfg(test)]
    pub fn contains(&self, key: Uuid) -> bool {
        self.by_id.contains_key(&key)
    }

    pub fn insert(&mut self, key: Uuid, value: PreconfRequestTypeB) {
        self.by_id.insert(key, value.clone());
        self.by_account.entry(value.signer().expect("signer")).or_default().push(key);
        self.reqs_by_slot.entry(value.target_slot()).or_default().push(key);
    }

    pub fn remove(&mut self, key: Uuid) -> Option<PreconfRequestTypeB> {
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
    pub fn fetch_preconf_requests_for_slot(&self, slot: u64) -> Option<Vec<PreconfRequestTypeB>> {
        self.reqs_by_slot
            .get(&slot)
            .map(|ids| ids.iter().filter_map(|id| self.by_id.get(id)).cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, PrimitiveSignature, U256};
    use taiyi_primitives::{BlockspaceAllocation, PreconfRequestTypeB};
    use uuid::Uuid;

    use super::Pending;

    #[test]
    fn test_add_remove_request() {
        let mut pending = Pending::new();
        let request = PreconfRequestTypeB {
            allocation: BlockspaceAllocation::default(),
            alloc_sig: PrimitiveSignature::new(U256::ZERO, U256::ZERO, false),
            transaction: None,
            signer: Some(Address::default()),
        };

        let id = Uuid::new_v4();
        pending.insert(id, request.clone());
        assert!(pending.contains(id));
        assert_eq!(pending.get(id), Some(request.clone()));

        pending.remove(id);
        assert_eq!(pending.get(id), None);
    }

    #[test]
    fn test_get_pending_diffs_for_account_after_insert_multiple_and_remove() {
        let mut pending = Pending::new();
        let account = Address::default();

        let request1 = PreconfRequestTypeB {
            allocation: BlockspaceAllocation { deposit: U256::from(100), ..Default::default() },
            alloc_sig: PrimitiveSignature::new(U256::ZERO, U256::ZERO, false),
            transaction: None,
            signer: Some(account),
        };
        let request2 = PreconfRequestTypeB {
            allocation: BlockspaceAllocation { deposit: U256::from(200), ..Default::default() },
            alloc_sig: PrimitiveSignature::new(U256::ZERO, U256::ZERO, false),
            transaction: None,
            signer: Some(account),
        };

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        pending.insert(id1, request1.clone());
        pending.insert(id2, request2.clone());

        assert_eq!(pending.get_pending_diffs_for_account(account), Some(U256::from(300)));

        pending.remove(id1);
        assert_eq!(pending.get_pending_diffs_for_account(account), Some(U256::from(200)));

        pending.remove(id2);
        assert_eq!(pending.get_pending_diffs_for_account(account), None);
    }
}
