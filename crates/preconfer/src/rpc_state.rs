use alloy::providers::{Provider, ProviderBuilder};
use reth::primitives::{Address, B256, U256};

#[derive(Debug, Clone, Copy, Default)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: U256,
    pub _code: B256,
}

pub async fn get_account_state(rpc: String, address: Address) -> eyre::Result<AccountState> {
    let url = rpc.parse()?;
    let provider = ProviderBuilder::new().on_http(url);
    let account = provider.get_account(address).await?;
    Ok(AccountState {
        nonce: account.nonce,
        balance: account.balance,
        _code: account.code_hash,
    })
}
