use reth::primitives::{Address, B256, U256};
use reth_db::Database;
use reth_provider::ProviderFactory;

use super::priortised_orderpool::AccountNonce;
use crate::reth_db_utils::noncer::NonceCache;

pub async fn update_onchain_nonces<DB: Database>(
    accounts: Vec<Address>,
    provider_factory: ProviderFactory<DB>,
    parent_block: B256,
) -> eyre::Result<Vec<AccountNonce>> {
    let nonce_cache = NonceCache::new(provider_factory, parent_block);
    let nonce_db_ref = nonce_cache.get_ref()?;
    let mut nonces = Vec::new();
    for account in accounts {
        let nonce = U256::from(nonce_db_ref.nonce(account)?);
        nonces.push(AccountNonce { account, nonce });
    }
    Ok(nonces)
}
