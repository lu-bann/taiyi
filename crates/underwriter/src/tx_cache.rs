use alloy::consensus::TxEnvelope;
use std::collections::{hash_map::Entry, HashMap};
use taiyi_primitives::{PreconfRequest, PreconfRequestTypeB};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum TxCacheError {
    #[error("No reserved transaction for id {id}")]
    MissingReservedTransaction { id: Uuid },

    #[error("No reserved transaction for slot {slot}")]
    MissingSlotReservations { slot: u64 },
}

pub type TxCacheResult<T> = Result<T, TxCacheError>;

#[derive(Debug, Default)]
pub struct TxCache {
    reserved_with_calldata: Vec<PreconfRequest>,
    reserved_without_calldata: HashMap<Uuid, PreconfRequestTypeB>,
}

impl TxCache {
    pub fn new() -> Self {
        Self { reserved_with_calldata: vec![], reserved_without_calldata: HashMap::new() }
    }

    pub fn add_with_calldata(&mut self, request: PreconfRequest) {
        self.reserved_with_calldata.push(request);
    }

    pub fn add_without_calldata(&mut self, id: Uuid, request: PreconfRequestTypeB) {
        self.reserved_without_calldata.insert(id, request);
    }

    pub fn add_calldata(&mut self, id: Uuid, tx: TxEnvelope) -> TxCacheResult<PreconfRequestTypeB> {
        let mut request = self
            .reserved_without_calldata
            .remove(&id)
            .ok_or(TxCacheError::MissingReservedTransaction { id })?;
        request.transaction = Some(tx);
        let preconf_request = PreconfRequest::TypeB(request.clone());
        self.reserved_with_calldata.push(preconf_request);
        Ok(request)
    }

    pub fn take(&mut self) -> (Vec<PreconfRequest>, Vec<PreconfRequestTypeB>) {
        (
            self.reserved_with_calldata.drain(..).collect(),
            self.reserved_without_calldata.drain().map(|(_, request)| request).collect(),
        )
    }
}

#[derive(Debug, Default)]
pub struct TxCachePerSlot {
    caches: HashMap<u64, TxCache>,
}

impl TxCachePerSlot {
    pub fn new() -> Self {
        Self { caches: HashMap::new() }
    }

    pub fn add_with_calldata(&mut self, slot: u64, request: PreconfRequest) {
        if let Entry::Vacant(e) = self.caches.entry(slot) {
            e.insert(TxCache::new());
        }
        self.caches.get_mut(&slot).expect("Must be available").add_with_calldata(request);
    }

    pub fn add_without_calldata(&mut self, slot: u64, id: Uuid, request: PreconfRequestTypeB) {
        if let Entry::Vacant(e) = self.caches.entry(slot) {
            e.insert(TxCache::new());
        }
        self.caches.get_mut(&slot).expect("Must be available").add_without_calldata(id, request);
    }

    pub fn add_calldata(
        &mut self,
        slot: u64,
        id: Uuid,
        tx: TxEnvelope,
    ) -> TxCacheResult<PreconfRequestTypeB> {
        self.caches
            .get_mut(&slot)
            .ok_or(TxCacheError::MissingSlotReservations { slot })?
            .add_calldata(id, tx)
    }

    pub async fn take(
        &mut self,
        slot: u64,
    ) -> TxCacheResult<(Vec<PreconfRequest>, Vec<PreconfRequestTypeB>)> {
        if let Entry::Vacant(e) = self.caches.entry(slot) {
            e.insert(TxCache::new());
        }
        Ok(self.caches.get_mut(&slot).ok_or(TxCacheError::MissingSlotReservations { slot })?.take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::consensus::{TxEip1559, TxEnvelope};
    use alloy::primitives::{Address, Signature, U256};
    use taiyi_primitives::{BlockspaceAllocation, PreconfFee, PreconfRequest, PreconfRequestTypeA};

    fn create_test_transaction() -> TxEnvelope {
        let signature = Signature::new(U256::ONE, U256::default(), false);
        TxEnvelope::new_unhashed(TxEip1559::default().into(), signature)
    }

    fn create_test_preconf_request_type_a() -> PreconfRequest {
        PreconfRequest::TypeA(PreconfRequestTypeA {
            preconf_tx: vec![create_test_transaction()],
            tip_transaction: create_test_transaction(),
            target_slot: 42,
            sequence_number: Some(1),
            signer: Address::random(),
            preconf_fee: PreconfFee { gas_fee: 10, blob_gas_fee: 150 },
        })
    }

    fn create_test_preconf_request_type_b() -> PreconfRequestTypeB {
        let signature = Signature::new(U256::ONE, U256::default(), false);
        PreconfRequestTypeB {
            allocation: BlockspaceAllocation {
                target_slot: 42,
                gas_limit: 21000,
                blob_count: 0,
                sender: Address::random(),
                recipient: Address::random(),
                deposit: U256::from(100),
                tip: U256::from(50),
                preconf_fee: PreconfFee { gas_fee: 10, blob_gas_fee: 150 },
            },
            alloc_sig: signature,
            transaction: None,
            signer: Address::random(),
        }
    }

    #[test]
    fn test_new_cache_is_empty() {
        let cache = TxCache::new();
        assert_eq!(cache.reserved_with_calldata.len(), 0);
        assert_eq!(cache.reserved_without_calldata.len(), 0);
    }

    #[test]
    fn test_add_with_calldata() {
        let mut cache = TxCache::new();
        let request = create_test_preconf_request_type_a();

        cache.add_with_calldata(request);

        assert_eq!(cache.reserved_with_calldata.len(), 1);
        assert_eq!(cache.reserved_without_calldata.len(), 0);
    }

    #[test]
    fn test_add_without_calldata() {
        let mut cache = TxCache::new();
        let id = Uuid::new_v4();
        let request = create_test_preconf_request_type_b();

        cache.add_without_calldata(id, request);

        assert_eq!(cache.reserved_with_calldata.len(), 0);
        assert_eq!(cache.reserved_without_calldata.len(), 1);
        assert!(cache.reserved_without_calldata.contains_key(&id));
    }

    #[test]
    fn test_add_calldata_success() {
        let mut cache = TxCache::new();
        let id = Uuid::new_v4();
        let mut request = create_test_preconf_request_type_b();
        request.transaction = None; // Ensure it starts without transaction
        let tx = create_test_transaction();

        cache.add_without_calldata(id, request);
        let result = cache.add_calldata(id, tx.clone());

        assert!(result.is_ok());
        let returned_request = result.unwrap();
        assert!(returned_request.transaction.is_some());
        assert_eq!(cache.reserved_with_calldata.len(), 1);
        assert_eq!(cache.reserved_without_calldata.len(), 0);
    }

    #[test]
    fn test_add_calldata_missing_id() {
        let mut cache = TxCache::new();
        let id = Uuid::new_v4();
        let tx = create_test_transaction();

        let result = cache.add_calldata(id, tx);

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            TxCacheError::MissingReservedTransaction { id: error_id } => {
                assert_eq!(error_id, id);
            }
            _ => panic!("Expected MissingReservedTransaction error"),
        }
    }

    #[test]
    fn test_take_drains_both_collections() {
        let mut cache = TxCache::new();
        let id = Uuid::new_v4();
        let preconf_request = create_test_preconf_request_type_a();
        let type_b_request = create_test_preconf_request_type_b();

        cache.add_with_calldata(preconf_request);
        cache.add_without_calldata(id, type_b_request);

        let (with_calldata, without_calldata) = cache.take();

        assert_eq!(with_calldata.len(), 1);
        assert_eq!(without_calldata.len(), 1);
        assert_eq!(cache.reserved_with_calldata.len(), 0);
        assert_eq!(cache.reserved_without_calldata.len(), 0);
    }

    #[test]
    fn test_new_per_slot_cache_is_empty() {
        let cache = TxCachePerSlot::new();
        assert_eq!(cache.caches.len(), 0);
    }

    #[test]
    fn test_add_operations_create_slot_cache() {
        let mut cache = TxCachePerSlot::new();
        let slot = 42u64;
        let request = create_test_preconf_request_type_a();

        cache.add_with_calldata(slot, request);

        assert_eq!(cache.caches.len(), 1);
        assert!(cache.caches.contains_key(&slot));
    }

    #[test]
    fn test_multiple_slots_isolation() {
        let mut cache = TxCachePerSlot::new();
        let slot1 = 42u64;
        let slot2 = 43u64;
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let request1 = create_test_preconf_request_type_b();
        let request2 = create_test_preconf_request_type_b();

        cache.add_without_calldata(slot1, id1, request1);
        cache.add_without_calldata(slot2, id2, request2);

        assert_eq!(cache.caches.len(), 2);
        assert!(cache.caches.contains_key(&slot1));
        assert!(cache.caches.contains_key(&slot2));
    }

    #[test]
    fn test_add_calldata_missing_slot() {
        let mut cache = TxCachePerSlot::new();
        let slot = 42u64;
        let id = Uuid::new_v4();
        let tx = create_test_transaction();

        let result = cache.add_calldata(slot, id, tx);

        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            TxCacheError::MissingSlotReservations { slot: error_slot } => {
                assert_eq!(error_slot, slot);
            }
            _ => panic!("Expected MissingSlotReservations error"),
        }
    }

    #[tokio::test]
    async fn test_take_with_auto_creation() {
        let mut cache = TxCachePerSlot::new();
        let slot = 42u64;

        let result = cache.take(slot).await;

        assert!(result.is_ok());
        let (with_calldata, without_calldata) = result.unwrap();
        assert_eq!(with_calldata.len(), 0);
        assert_eq!(without_calldata.len(), 0);
        assert!(cache.caches.contains_key(&slot));
    }
}
