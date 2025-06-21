use alloy_consensus::TxEnvelope;
use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
};
use taiyi_primitives::{PreconfRequest, PreconfRequestTypeB};
use thiserror::Error;
use tokio::sync::RwLock;
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

#[derive(Debug, Clone, Default)]
pub struct TxCachePerSlot {
    caches: Arc<RwLock<HashMap<u64, TxCache>>>,
}

impl TxCachePerSlot {
    pub fn new() -> Self {
        Self { caches: Arc::new(RwLock::new(HashMap::new())) }
    }

    pub async fn add_with_calldata(&mut self, slot: u64, request: PreconfRequest) {
        let mut caches = self.caches.write().await;
        if let Entry::Vacant(e) = caches.entry(slot) {
            e.insert(TxCache::new());
        }
        caches.get_mut(&slot).expect("Must be available").add_with_calldata(request);
    }

    pub async fn add_without_calldata(
        &mut self,
        slot: u64,
        id: Uuid,
        request: PreconfRequestTypeB,
    ) {
        let mut caches = self.caches.write().await;
        if let Entry::Vacant(e) = caches.entry(slot) {
            e.insert(TxCache::new());
        }
        caches.get_mut(&slot).expect("Must be available").add_without_calldata(id, request);
    }

    pub async fn add_calldata(
        &mut self,
        slot: u64,
        id: Uuid,
        tx: TxEnvelope,
    ) -> TxCacheResult<PreconfRequestTypeB> {
        let mut caches = self.caches.write().await;
        caches
            .get_mut(&slot)
            .ok_or(TxCacheError::MissingSlotReservations { slot })?
            .add_calldata(id, tx)
    }

    pub async fn take(
        &mut self,
        slot: u64,
    ) -> TxCacheResult<(Vec<PreconfRequest>, Vec<PreconfRequestTypeB>)> {
        let mut caches = self.caches.write().await;
        if let Entry::Vacant(e) = caches.entry(slot) {
            e.insert(TxCache::new());
        }
        Ok(caches.get_mut(&slot).ok_or(TxCacheError::MissingSlotReservations { slot })?.take())
    }
}
