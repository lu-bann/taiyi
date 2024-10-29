#![allow(dead_code)]
use std::sync::Arc;

use alloy_primitives::{Address, StorageKey, StorageValue, B256, U256};
use reth_payload_builder::database::CachedReads;
use reth_provider::{ProviderError, StateProviderBox};
use reth_revm::{
    database::StateProviderDatabase,
    db::{BundleState, WrapDatabaseRef},
    primitives::KECCAK_EMPTY,
    Database, State,
};

#[derive(Clone)]
pub struct StateCacheDB {
    provider: Arc<StateProviderBox>,
    cached_reads: CachedReads,
    bundle_state: Option<BundleState>,
}

impl StateCacheDB {
    pub fn new(provider: Arc<StateProviderBox>) -> Self {
        Self {
            provider,
            cached_reads: CachedReads::default(),
            bundle_state: Some(BundleState::default()),
        }
    }

    pub fn provider(&self) -> &StateProviderBox {
        &self.provider
    }

    pub fn owned_provider(self) -> Arc<StateProviderBox> {
        self.provider
    }
    
    pub fn with_cached_reads(mut self, cached_reads: CachedReads) -> Self {
        self.cached_reads = cached_reads;
        self
    }

    pub fn with_bundle_state(mut self, bundle_state: BundleState) -> Self {
        self.bundle_state = Some(bundle_state);
        self
    }

    pub fn new_db_ref(&mut self) -> StateCacheDBRef<impl Database<Error = ProviderError> + '_> {
        let state_provider = StateProviderDatabase::new(&self.provider);
        let cache_db = WrapDatabaseRef(self.cached_reads.as_db(state_provider));
        let bundle_state = self.bundle_state.take().unwrap();
        let db = State::builder()
            .with_database(cache_db)
            .with_bundle_prestate(bundle_state)
            .with_bundle_update()
            .build();
        StateCacheDBRef::new(db, &mut self.bundle_state)
    }

    pub fn balance(&mut self, address: Address) -> Result<U256, ProviderError> {
        let mut db = self.new_db_ref();
        Ok(db.as_mut().basic(address)?.map(|acc| acc.balance).unwrap_or_default())
    }

    pub fn nonce(&mut self, address: Address) -> Result<u64, ProviderError> {
        let mut db = self.new_db_ref();
        Ok(db.as_mut().basic(address)?.map(|acc| acc.nonce).unwrap_or_default())
    }

    pub fn code_hash(&mut self, address: Address) -> Result<B256, ProviderError> {
        let mut db = self.new_db_ref();
        Ok(db.as_mut().basic(address)?.map(|acc| acc.code_hash).unwrap_or_else(|| KECCAK_EMPTY))
    }

    pub fn storage(
        &mut self,
        address: Address,
        storage_key: StorageKey,
    ) -> Result<StorageValue, ProviderError> {
        let mut db = self.new_db_ref();
        Ok(db.as_mut().storage(address, storage_key.into())?)
    }
}

pub struct StateCacheDBRef<'a, DB>
where
    DB: Database<Error = ProviderError>,
{
    db: State<DB>,
    parent_bundle_state_ref: &'a mut Option<BundleState>,
}

impl<'a, DB> StateCacheDBRef<'a, DB>
where
    DB: Database<Error = ProviderError>,
{
    pub fn new(db: State<DB>, parent_bundle_state_ref: &'a mut Option<BundleState>) -> Self {
        Self { db, parent_bundle_state_ref }
    }

    pub fn db(&self) -> &State<DB> {
        &self.db
    }
}

impl<'a, DB> Drop for StateCacheDBRef<'a, DB>
where
    DB: Database<Error = ProviderError>,
{
    fn drop(&mut self) {
        *self.parent_bundle_state_ref = Some(self.db.take_bundle())
    }
}

impl<'a, DB> AsRef<State<DB>> for StateCacheDBRef<'a, DB>
where
    DB: Database<Error = ProviderError>,
{
    fn as_ref(&self) -> &State<DB> {
        &self.db
    }
}

impl<'a, DB> AsMut<State<DB>> for StateCacheDBRef<'a, DB>
where
    DB: Database<Error = ProviderError>,
{
    fn as_mut(&mut self) -> &mut State<DB> {
        &mut self.db
    }
}
