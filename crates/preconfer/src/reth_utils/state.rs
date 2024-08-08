#![allow(dead_code)]
use ahash::HashMap;
use reth::primitives::{Address, U256};
use reth::providers::{ProviderFactory, StateProviderBox};
use reth_chainspec::ChainSpec;
use reth_db::database::Database;
use reth_errors::ProviderResult;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, Default)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: U256,
    pub has_code: bool,
}

#[derive(Debug)]
pub struct StateCache<DB> {
    provider_factory: ProviderFactory<DB>,
    cache: Arc<Mutex<HashMap<Address, AccountState>>>,
    block: u64,
}

impl<DB: Database> StateCache<DB> {
    pub fn new(provider_factory: ProviderFactory<DB>, block: u64) -> Self {
        Self {
            provider_factory,
            cache: Arc::new(Mutex::new(HashMap::default())),
            block,
        }
    }

    pub fn get_ref(&self) -> ProviderResult<StateCacheRef> {
        let state = self.provider_factory.history_by_block_number(self.block)?;
        Ok(StateCacheRef {
            state,
            cache: Arc::clone(&self.cache),
        })
    }
}

pub struct StateCacheRef {
    state: StateProviderBox,
    cache: Arc<Mutex<HashMap<Address, AccountState>>>,
}

impl StateCacheRef {
    pub fn state(&self, address: Address) -> ProviderResult<AccountState> {
        let mut cache = self.cache.lock().expect("lock cache");
        if let Some(state) = cache.get(&address) {
            return Ok(*state);
        }
        let nonce = self.state.account_nonce(address)?.unwrap_or_default();
        let balance = self.state.account_balance(address)?.unwrap_or_default();
        let has_code = self.state.account_code(address)?.is_some();
        let state = AccountState {
            nonce,
            balance,
            has_code,
        };
        cache.insert(address, state);
        Ok(state)
    }
}

pub async fn state(
    account: Address,
    parent_block: u64,
    chain_spec: Arc<ChainSpec>,
) -> eyre::Result<AccountState> {
    let provider_factory = crate::reth_utils::db_provider::reth_db_provider(chain_spec);
    let state_cache = StateCache::new(provider_factory, parent_block);
    let state_db_ref = state_cache.get_ref()?;
    let state = state_db_ref.state(account)?;
    Ok(state)
}
