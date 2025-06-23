use crate::account_info::{AccountInfo, AccountInfoProvider, AccountInfoProviderError};
use alloy_primitives::{Address, U256};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::error;

#[derive(Debug, Error, PartialEq)]
pub enum AccountError {
    #[error("Failed to query account for {owner}")]
    FailedQuery { owner: Address },

    #[error("Balance too low (balance={balance}, required={required})")]
    BalanceTooLow { balance: U256, required: U256 },

    #[error("Invalid nonce (nonce={nonce}, expected={expected})")]
    InvalidNonce { nonce: u64, expected: u64 },

    #[error("{0}")]
    AccountInfoProvider(#[from] AccountInfoProviderError),
}

pub type AccountResult<T> = Result<T, AccountError>;

fn verify_balance(balance: U256, required: U256) -> AccountResult<()> {
    if required > balance {
        return Err(AccountError::BalanceTooLow { required, balance });
    }
    Ok(())
}

fn verify_nonce(nonce: u64, expected: u64) -> AccountResult<()> {
    if nonce != expected {
        return Err(AccountError::InvalidNonce { nonce, expected });
    }
    Ok(())
}

#[derive(Debug, PartialEq)]
pub struct AccountInfoMeta {
    pub owner: Address,
    pub slot: u64,
    pub info: AccountInfo,
}

impl AccountInfoMeta {
    pub fn new(owner: Address, slot: u64) -> Self {
        Self { owner, slot, info: AccountInfo::default() }
    }

    pub fn reserve(&mut self, tx_count: u64, amount: U256) {
        self.info.reserve(tx_count, amount);
    }
}

#[derive(Debug, Default)]
pub struct AccountState<Provider: AccountInfoProvider> {
    accounts: RwLock<Vec<AccountInfoMeta>>,
    last_slot: Arc<AtomicU64>,
    state_provider: Provider,
}

impl<Provider: AccountInfoProvider> AccountState<Provider> {
    pub fn new(last_slot: Arc<AtomicU64>, state_provider: Provider) -> Self {
        Self { accounts: vec![].into(), last_slot, state_provider }
    }

    async fn get_from_provider(&self, owner: &Address) -> AccountResult<AccountInfo> {
        Ok(self.state_provider.get(owner).await?)
    }

    pub async fn get(&self, owner: &Address) -> AccountResult<AccountInfo> {
        let mut on_chain_account_info = self.get_from_provider(owner).await?;
        let slot = self.last_slot.load(Ordering::Relaxed) + 1;
        if let Some(meta) =
            self.accounts.read().await.iter().find(|meta| &meta.owner == owner && meta.slot == slot)
        {
            on_chain_account_info.tx_count += meta.info.tx_count;
            on_chain_account_info.amount -= meta.info.amount;
        }
        Ok(on_chain_account_info)
    }

    async fn assert_account_info(
        &self,
        owner: &Address,
        nonce: u64,
        tx_count: u64,
        amount: U256,
    ) -> AccountResult<()> {
        let on_chain_account_info = self.get_from_provider(owner).await?;
        verify_balance(on_chain_account_info.amount, amount)?;
        let expected_nonce = on_chain_account_info.tx_count + tx_count + 1;
        verify_nonce(nonce, expected_nonce)
    }

    pub async fn reserve(
        &self,
        owner: &Address,
        nonce: u64,
        tx_count: u64,
        amount: U256,
    ) -> AccountResult<()> {
        let mut accounts = self.accounts.write().await;
        let slot = self.last_slot.load(Ordering::Relaxed) + 1;
        accounts.retain(|meta| meta.slot == slot);
        if let Some(meta) =
            accounts.iter_mut().find(|meta| &meta.owner == owner && meta.slot == slot)
        {
            self.assert_account_info(owner, nonce, meta.info.tx_count, meta.info.amount + amount)
                .await?;
            meta.reserve(tx_count, amount);
        } else {
            self.assert_account_info(owner, nonce, 0, amount).await?;
            let mut meta = AccountInfoMeta::new(*owner, slot);
            meta.reserve(tx_count, amount);
            accounts.push(meta);
        }
        Ok(())
    }

    pub async fn verify_sufficient_balance(
        &self,
        owner: &Address,
        amount: U256,
    ) -> AccountResult<()> {
        let on_chain_account_info = self.get_from_provider(owner).await?;
        verify_balance(on_chain_account_info.amount, amount)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::account_info::MockAccountInfoProvider;
    use alloy_primitives::{address, Address};

    const DUMMY_OWNER: Address = address!("0x0000777735367b36bC9B61C50022d9D0700dB4Ec");

    #[tokio::test]
    async fn test_get_account_state_without_transactions() {
        let last_slot = Arc::new(0u64.into());
        let mut state_provider = MockAccountInfoProvider::new();
        state_provider
            .expect_get()
            .return_once(move |_| Box::pin(async { Ok(AccountInfo::default()) }));
        let account_state = AccountState::new(last_slot, state_provider);

        let account_info = account_state.get(&DUMMY_OWNER).await.unwrap();
        assert_eq!(account_info, AccountInfo::default())
    }

    #[tokio::test]
    async fn test_account_state_fails_if_provider_returns_error() {
        let last_slot = Arc::new(0u64.into());
        let mut state_provider = MockAccountInfoProvider::new();
        state_provider.expect_get().return_once(move |_| {
            Box::pin(async {
                let _ = i32::from_str_radix("a12", 10)?;
                Ok(AccountInfo::default())
            })
        });
        let account_state = AccountState::new(last_slot, state_provider);

        assert!(account_state.get(&DUMMY_OWNER).await.is_err());
    }

    #[tokio::test]
    async fn reserve_fails_if_balance_is_too_low() {
        let last_slot = Arc::new(0u64.into());
        let balance = U256::from(1000);
        let provider_balance = balance.clone();
        let mut state_provider = MockAccountInfoProvider::new();
        state_provider.expect_get().return_once(move |_| {
            Box::pin(async move { Ok(AccountInfo::new(0, provider_balance)) })
        });
        let account_state = AccountState::new(last_slot, state_provider);

        let amount = U256::from(1012);
        let nonce = 1;
        let tx_count = 1;
        let err = account_state.reserve(&DUMMY_OWNER, nonce, tx_count, amount).await.unwrap_err();

        assert_eq!(err, AccountError::BalanceTooLow { required: amount, balance });
    }

    #[tokio::test]
    async fn reserve_works() {
        let last_slot = Arc::new(0u64.into());
        let mut state_provider = MockAccountInfoProvider::new();
        state_provider
            .expect_get()
            .returning(|_| Box::pin(async { Ok(AccountInfo::new(0, U256::from(1000))) }));
        let account_state = AccountState::new(last_slot, state_provider);

        let amount = U256::from(400);
        let nonce = 1;
        let tx_count = 1;
        assert!(account_state.reserve(&DUMMY_OWNER, nonce, tx_count, amount).await.is_ok());

        let info = account_state.get(&DUMMY_OWNER).await.unwrap();
        assert_eq!(info, AccountInfo::new(1, U256::from(600)));
    }

    #[tokio::test]
    async fn reserve_fails_if_balance_is_too_low_after_second_reservation_in_same_slot() {
        let last_slot = Arc::new(0u64.into());
        let balance = U256::from(1000);
        let mut state_provider = MockAccountInfoProvider::new();
        state_provider
            .expect_get()
            .returning(|_| Box::pin(async { Ok(AccountInfo::new(0, U256::from(1000))) }));
        let account_state = AccountState::new(last_slot, state_provider);

        let amount = U256::from(400);
        let nonce = 1;
        let tx_count = 1;
        assert!(account_state.reserve(&DUMMY_OWNER, nonce, tx_count, amount).await.is_ok());

        let amount = U256::from(612);
        let nonce = 2;
        let err = account_state.reserve(&DUMMY_OWNER, nonce, tx_count, amount).await.unwrap_err();

        assert_eq!(err, AccountError::BalanceTooLow { required: U256::from(1012), balance });
    }

    #[tokio::test]
    async fn test_account_state_gets_reset_when_slot_changes() {
        let last_slot = Arc::new(AtomicU64::new(0u64));
        let mut state_provider = MockAccountInfoProvider::new();
        state_provider
            .expect_get()
            .returning(|_| Box::pin(async { Ok(AccountInfo::new(0, U256::from(1000))) }));
        let account_state = AccountState::new(last_slot.clone(), state_provider);

        let amount = U256::from(500);
        let nonce = 1;
        let tx_count = 1;
        assert!(account_state.reserve(&DUMMY_OWNER, nonce, tx_count, amount).await.is_ok());

        last_slot.store(1u64, Ordering::Relaxed);

        let info = account_state.get(&DUMMY_OWNER).await.unwrap();
        assert_eq!(info, AccountInfo::new(0, U256::from(1000)));
    }

    #[tokio::test]
    async fn reserve_fails_if_nonce_is_too_low() {
        let last_slot = Arc::new(0u64.into());
        let mut state_provider = MockAccountInfoProvider::new();
        state_provider
            .expect_get()
            .returning(|_| Box::pin(async { Ok(AccountInfo::new(2, U256::from(1000))) }));
        let account_state = AccountState::new(last_slot, state_provider);

        let amount = U256::from(400);
        let nonce = 2;
        let tx_count = 1;
        let err = account_state.reserve(&DUMMY_OWNER, nonce, tx_count, amount).await.unwrap_err();
        assert_eq!(err, AccountError::InvalidNonce { nonce, expected: 3 });
        let nonce = 3;
        assert!(account_state.reserve(&DUMMY_OWNER, nonce, tx_count, amount).await.is_ok());
        let err = account_state.reserve(&DUMMY_OWNER, nonce, tx_count, amount).await.unwrap_err();
        assert_eq!(err, AccountError::InvalidNonce { nonce, expected: 4 });
    }

    #[tokio::test]
    async fn reserve_fails_if_nonce_is_too_high() {
        let last_slot = Arc::new(0u64.into());
        let mut state_provider = MockAccountInfoProvider::new();
        state_provider
            .expect_get()
            .returning(|_| Box::pin(async { Ok(AccountInfo::new(2, U256::from(1000))) }));
        let account_state = AccountState::new(last_slot, state_provider);

        let amount = U256::from(400);
        let nonce = 4;
        let tx_count = 1;
        let err = account_state.reserve(&DUMMY_OWNER, nonce, tx_count, amount).await.unwrap_err();
        assert_eq!(err, AccountError::InvalidNonce { nonce, expected: 3 });
        let nonce = 3;
        assert!(account_state.reserve(&DUMMY_OWNER, nonce, tx_count, amount).await.is_ok());
        let nonce = 5;
        let err = account_state.reserve(&DUMMY_OWNER, nonce, tx_count, amount).await.unwrap_err();
        assert_eq!(err, AccountError::InvalidNonce { nonce, expected: 4 });
    }

    #[tokio::test]
    async fn verify_sufficient_balance_fails_for_insufficient_balance() {
        let last_slot = Arc::new(0u64.into());
        let mut state_provider = MockAccountInfoProvider::new();
        state_provider
            .expect_get()
            .return_once(|_| Box::pin(async { Ok(AccountInfo::new(2, U256::from(1000))) }));
        let account_state = AccountState::new(last_slot, state_provider);

        let amount = U256::from(1002);
        let err = account_state.verify_sufficient_balance(&DUMMY_OWNER, amount).await.unwrap_err();
        assert_eq!(
            err,
            AccountError::BalanceTooLow { balance: U256::from(1000), required: amount }
        );
    }

    #[tokio::test]
    async fn verify_sufficient_balance_works_for_sufficient_balance() {
        let last_slot = Arc::new(0u64.into());
        let mut state_provider = MockAccountInfoProvider::new();
        state_provider
            .expect_get()
            .return_once(|_| Box::pin(async { Ok(AccountInfo::new(2, U256::from(1000))) }));
        let account_state = AccountState::new(last_slot, state_provider);

        let amount = U256::from(100);
        assert!(account_state.verify_sufficient_balance(&DUMMY_OWNER, amount).await.is_ok());
    }
}
