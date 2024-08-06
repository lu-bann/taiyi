use crate::reth_db_utils::state::NonceCache;
use reth::primitives::Address;

pub async fn get_nonce(account: Address, parent_block: u64) -> eyre::Result<u64> {
    let provider_factory = crate::reth_db_utils::db_provider::reth_db_provider();
    let nonce_cache = NonceCache::new(provider_factory, parent_block);
    let nonce_db_ref = nonce_cache.get_ref()?;
    let nonce = nonce_db_ref.nonce(account)?;
    Ok(nonce)
}
