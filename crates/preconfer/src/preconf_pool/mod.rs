use std::{collections::HashMap, future::Future, sync::Arc};

use alloy_consensus::{Transaction, TxEnvelope};
use alloy_eips::eip4844::DATA_GAS_PER_BLOB;
use alloy_primitives::{Address, U256};
use ethereum_consensus::{clock::from_system_time, deneb::Context};
use futures::StreamExt;
use inner::BlockspaceAvailable;
use parking_lot::RwLock;
use pending::Pending;
use ready::Ready;
use reqwest::Url;
use taiyi_primitives::{
    PreconfFeeResponse, PreconfRequest, PreconfRequestTypeA, PreconfRequestTypeB,
};
use tracing::info;
use uuid::Uuid;
use validator::PreconfValidator;

use crate::{
    clients::execution_client::AccountState,
    context_ext::ContextExt,
    error::{PoolError, ValidationError},
    preconf_pool::inner::PreconfPoolInner,
};

mod inner;
mod pending;
mod ready;
#[cfg(test)]
mod tests;
mod validator;

#[derive(Debug)]
pub struct PreconfPoolBuilder;

impl PreconfPoolBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(self, rpc_url: Url, taiyi_escrow_address: Address) -> Arc<PreconfPool> {
        let validator = PreconfValidator::new(rpc_url);
        Arc::new(PreconfPool::new(validator, taiyi_escrow_address))
    }
}

/// A pool that manages preconf requests.
/// This pool maintains the state of all preconf requests and stores them accordingly.
#[derive(Debug)]
pub struct PreconfPool {
    /// Inner type containing all sub-pools
    pool_inner: RwLock<PreconfPoolInner>,
    /// Validator to validate preconf requests.
    validator: PreconfValidator,
    /// escrow contract
    pub taiyi_escrow_address: Address,
    /// Account state cache
    state_cache: RwLock<HashMap<Address, AccountState>>,
}

impl PreconfPool {
    pub fn new(validator: PreconfValidator, taiyi_escrow_address: Address) -> Self {
        Self {
            pool_inner: RwLock::new(PreconfPoolInner {
                pending: Pending::new(),
                ready: Ready::default(),
                blockspace_issued: HashMap::new(),
            }),
            validator,
            taiyi_escrow_address,
            state_cache: RwLock::new(HashMap::new()),
        }
    }

    pub async fn state_cache_cleanup(
        self: Arc<Self>,
        context: Context,
    ) -> impl Future<Output = eyre::Result<()>> {
        let clock = from_system_time(
            context.actual_genesis_time(),
            context.seconds_per_slot,
            context.slots_per_epoch,
        );
        let mut slot_stream = clock.into_stream();

        async move {
            while (slot_stream.next().await).is_some() {
                let accounts_to_check = {
                    let cache = self.state_cache.read();
                    cache.keys().cloned().collect::<Vec<Address>>()
                };

                // Accounts which don't have any preconf requests in the pool
                let accounts_to_remove: Vec<Address> = accounts_to_check
                    .into_iter()
                    .filter(|&address| !self.has_preconf_requests(address))
                    .collect();

                if !accounts_to_remove.is_empty() {
                    let mut cache = self.state_cache.write();
                    for address in accounts_to_remove {
                        cache.remove(&address);
                    }
                }
            }

            info!("Shutting down state cache cleanup task");
            Ok(())
        }
    }

    pub async fn reserve_blockspace(
        &self,
        preconf_request: PreconfRequestTypeB,
        preconf_fee: PreconfFeeResponse,
    ) -> Result<Uuid, PoolError> {
        // check if the sender has enough balance to lock the deposit
        self.has_enough_balance(preconf_request.signer(), preconf_request.preconf_tip()).await?;

        let mut pool_inner = self.pool_inner.write();

        let mut blockspace_avail =
            match pool_inner.blockspace_issued.get(&preconf_request.target_slot()) {
                Some(space) => space.clone(),
                None => BlockspaceAvailable::default(),
            };

        // Verify that we have enough space
        if blockspace_avail.gas_limit <= preconf_request.allocation.gas_limit
            || blockspace_avail.blobs <= preconf_request.allocation.blob_count
        {
            return Err(PoolError::BlockspaceNotAvailable);
        }

        // Verify preconf tips
        let expected_tip = U256::from(
            preconf_request.allocation.gas_limit as u128 * preconf_fee.gas_fee
                + (preconf_request.allocation.blob_count as u128)
                    * DATA_GAS_PER_BLOB as u128
                    * preconf_fee.blob_gas_fee,
        );
        if preconf_request.preconf_tip() <= expected_tip {
            return Err(PoolError::Validation(ValidationError::InsufficientTip(
                expected_tip,
                preconf_request.preconf_tip(),
            )));
        }

        // calculate diffs
        blockspace_avail.gas_limit -= preconf_request.allocation.gas_limit;
        blockspace_avail.blobs -= preconf_request.allocation.blob_count;
        blockspace_avail.num_of_constraints -= 1;

        let request_id = Uuid::new_v4();

        // Update the blockspace issued for the target slot and insert the request into the pending pool
        pool_inner.update_blockspace(preconf_request.target_slot(), blockspace_avail);
        pool_inner.pending.insert(request_id, preconf_request);

        Ok(request_id)
    }

    /// Validates the transactions in the preconf request and stores it in the ready pool.
    pub async fn validate_and_store(
        &self,
        preconf_request: PreconfRequest,
        request_id: Uuid,
        preconf_fee: PreconfFeeResponse,
    ) -> Result<PreconfRequest, PoolError> {
        let mut account_state = self.state_cache.read().get(&preconf_request.signer()).cloned();

        if account_state.is_none() {
            let state = self
                .validator
                .execution_client
                .get_account_state(preconf_request.signer())
                .await
                .map_err(|_| ValidationError::AccountStateNotFound(preconf_request.signer()))?;

            self.state_cache.write().insert(preconf_request.signer(), state.clone());
            account_state = Some(state);
        }

        match preconf_request {
            PreconfRequest::TypeA(preconf_request) => {
                self.validate_typea(
                    &preconf_request,
                    &account_state.expect("can't be none"),
                    preconf_fee,
                )
                .await?;
                Ok(self.insert_ready(request_id, PreconfRequest::TypeA(preconf_request)))
            }
            PreconfRequest::TypeB(preconf_request) => {
                if preconf_request.transaction.is_some() {
                    self.validate_typeb(&preconf_request, &account_state.expect("can't be none"))
                        .await?;
                    // Move the request from pending to ready pool
                    self.delete_pending(request_id);
                    Ok(self.insert_ready(request_id, PreconfRequest::TypeB(preconf_request)))
                } else {
                    Err(PoolError::TransactionNotFound)
                }
            }
        }
    }

    pub async fn has_enough_balance(
        &self,
        account: Address,
        preconf_tip: U256,
    ) -> Result<(), PoolError> {
        let pending_diffs_for_account = self.pool_inner.read().escrow_balance_diffs(account);
        let escrow_balance =
            self.validator.execution_client.balance_of(account, self.taiyi_escrow_address).await;

        match escrow_balance {
            Ok(balance) => {
                let effective_balance =
                    balance - U256::from(pending_diffs_for_account.unwrap_or_default());
                if effective_balance < preconf_tip {
                    Err(PoolError::InsufficientEscrowBalance(effective_balance, preconf_tip))
                } else {
                    Ok(())
                }
            }
            Err(_) => Err(PoolError::EscrowBalanceNotFoundForAccount(account)),
        }
    }

    async fn validate_typea(
        &self,
        preconf_request: &PreconfRequestTypeA,
        account_state: &AccountState,
        preconf_fee: PreconfFeeResponse,
    ) -> eyre::Result<(), ValidationError> {
        // Tip transaction must be an ETH transfer
        if !preconf_request.tip_transaction.is_eip1559() {
            return Err(ValidationError::InvalidTipTransaction);
        }

        let request_gas_limit = preconf_request.tip_transaction.gas_limit()
            + preconf_request.preconf_tx.iter().map(|tx| tx.gas_limit()).sum::<u64>();

        let mut blob_count = 0;
        for preconf_tx in preconf_request.preconf_tx.clone() {
            if preconf_tx.is_eip4844() {
                blob_count += preconf_tx
                    .as_eip4844()
                    .expect("Failed to decode 4844 transaction")
                    .tx()
                    .blob_versioned_hashes()
                    .iter()
                    .len();
            }
        }

        {
            let pool_inner = self.pool_inner.write();

            let blockspace_avail =
                match pool_inner.blockspace_issued.get(&preconf_request.target_slot()) {
                    Some(space) => space.clone(),
                    None => BlockspaceAvailable::default(),
                };

            // Verify that we have enough blockspace
            if blockspace_avail.gas_limit < request_gas_limit {
                return Err(ValidationError::GasLimitTooHigh);
            }

            if blockspace_avail.blobs < blob_count {
                return Err(ValidationError::BlobCountExceedsLimit(
                    blockspace_avail.blobs,
                    blob_count,
                ));
            }
        }

        // Validate preconf tip
        let expected_tip = U256::from(
            preconf_fee.gas_fee * request_gas_limit as u128
                + preconf_fee.blob_gas_fee * DATA_GAS_PER_BLOB as u128 * blob_count as u128,
        );

        if preconf_request.preconf_tip() <= expected_tip {
            return Err(ValidationError::InsufficientTip(
                expected_tip,
                preconf_request.preconf_tip(),
            ));
        }

        // State validation
        let account_balance = account_state.balance;
        let account_nonce = account_state.nonce;

        // Nonce check
        let nonce = preconf_request.tip_transaction.nonce();
        if nonce > account_nonce {
            return Err(ValidationError::NonceTooHigh(account_nonce, nonce));
        }
        if nonce < account_nonce {
            return Err(ValidationError::NonceTooLow(account_nonce, nonce));
        }

        let mut all_transactions = vec![preconf_request.tip_transaction.clone()];
        all_transactions.extend(preconf_request.preconf_tx.clone());
        Self::verify_nonce_continuity_and_signer(&all_transactions)?;

        // Balance check
        let total_value = preconf_request.value();
        if account_balance < total_value {
            return Err(ValidationError::LowBalance(total_value - account_balance));
        }

        // heavy blob tx validation
        for preconf_tx in preconf_request.preconf_tx.clone() {
            if preconf_tx.is_eip4844() {
                let transaction = preconf_tx
                    .as_eip4844()
                    .expect("Failed to decode 4844 transaction")
                    .tx()
                    .clone()
                    .try_into_4844_with_sidecar()
                    .map_err(|_| {
                        ValidationError::Internal("Failed to decode 4844 transaction".to_string())
                    })?;

                // validate the blob
                transaction.validate_blob(self.validator.kzg_settings.get())?;
            }
        }

        // Update state cache
        self.state_cache.write().insert(
            preconf_request.signer(),
            AccountState {
                balance: account_balance - total_value,
                nonce: account_nonce + preconf_request.preconf_tx.len() as u64 + 1,
            },
        );

        Ok(())
    }

    // NOTE: only checks account balance and nonce
    async fn validate_typeb(
        &self,
        preconf_request: &PreconfRequestTypeB,
        account_state: &AccountState,
    ) -> eyre::Result<(), ValidationError> {
        let transaction = match preconf_request.transaction.clone() {
            Some(transaction) => transaction,
            None => return Err(ValidationError::TransactionNotFound),
        };

        let account_balance = account_state.balance;
        let account_nonce = account_state.nonce;

        // Check if sender has enough balance to cover transaction cost
        // For EIP-1559 transactions: tx_value.
        let cost = transaction.value();

        if account_balance < cost {
            return Err(ValidationError::LowBalance(cost - account_balance));
        }

        // Check nocne
        // transaction nonce
        let nonce = transaction.nonce();
        if nonce != account_nonce {
            return Err(if nonce > account_nonce {
                ValidationError::NonceTooHigh(account_nonce, nonce)
            } else {
                ValidationError::NonceTooLow(account_nonce, nonce)
            });
        }

        // heavy blob tx validation
        if transaction.is_eip4844() {
            let transaction = transaction
                .as_eip4844()
                .expect("Failed to decode 4844 transaction")
                .tx()
                .clone()
                .try_into_4844_with_sidecar()
                .map_err(|_| {
                    ValidationError::Internal("Failed to decode 4844 transaction".to_string())
                })?;

            if preconf_request.allocation.blob_count < transaction.tx.blob_versioned_hashes.len() {
                return Err(ValidationError::BlobCountExceedsLimit(
                    preconf_request.allocation.blob_count,
                    transaction.tx.blob_versioned_hashes.len(),
                ));
            }

            // validate the blob
            transaction.validate_blob(self.validator.kzg_settings.get())?;
        }

        // Update state cache
        self.state_cache.write().insert(
            preconf_request.signer(),
            AccountState { balance: account_balance - cost, nonce: account_nonce + 1 },
        );

        Ok(())
    }

    /// Verifies that nonces in a sequence of transactions are continuous,
    /// with each transaction's nonce being exactly one more than the previous transaction's nonce.
    ///
    /// Also verifies that all transactions have the smae signer.
    fn verify_nonce_continuity_and_signer(
        transactions: &[TxEnvelope],
    ) -> Result<(), ValidationError> {
        if transactions.len() <= 1 {
            return Ok(());
        }

        // Recover the first signer
        let first_signer = transactions[0].recover_signer().map_err(|_| {
            ValidationError::Internal("Failed to recover signer from transaction".to_string())
        })?;

        let mut prev_nonce = transactions[0].nonce();
        for tx in &transactions[1..] {
            let signer = tx.recover_signer().map_err(|_| {
                ValidationError::Internal("Failed to recover signer from transaction".to_string())
            })?;

            if signer != first_signer {
                return Err(ValidationError::InvalidSigner(first_signer, signer));
            }

            let curr_nonce = tx.nonce();
            if curr_nonce != prev_nonce + 1 {
                return Err(ValidationError::InvalidNonceSequence(prev_nonce + 1, curr_nonce));
            }

            prev_nonce = curr_nonce;
        }

        Ok(())
    }

    /// Checks if an address has any preconf requests in the pool.
    pub fn has_preconf_requests(&self, address: Address) -> bool {
        self.pool_inner.read().has_preconf_requests(address)
    }

    /// Returns preconf requests in pending pool for a given slot.
    pub fn fetch_pending(&self, slot: u64) -> Option<Vec<PreconfRequestTypeB>> {
        self.pool_inner.write().pending.fetch_preconf_requests_for_slot(slot)
    }

    #[allow(dead_code)]
    /// Inserts a preconf request into the pending pool.
    pub fn insert_pending(&self, request_id: Uuid, preconf_request: PreconfRequestTypeB) {
        self.pool_inner.write().pending.insert(request_id, preconf_request);
    }

    /// Returns a preconf request from the pending pool.
    pub fn get_pending(&self, request_id: Uuid) -> Option<PreconfRequestTypeB> {
        self.pool_inner.read().pending.get(request_id)
    }

    /// Deletes a preconf request from the pending pool.
    pub fn delete_pending(&self, request_id: Uuid) -> Option<PreconfRequestTypeB> {
        self.pool_inner.write().pending.remove(request_id)
    }

    /// Inserts a preconf request into the ready sub-pool.
    fn insert_ready(&self, request_id: Uuid, preconf_request: PreconfRequest) -> PreconfRequest {
        self.pool_inner.write().ready.insert(request_id, preconf_request)
    }

    /// Returns preconf requests in ready pool.
    pub fn fetch_ready(&self, slot: u64) -> Result<Vec<PreconfRequest>, PoolError> {
        self.pool_inner.read().ready.fetch_preconf_requests_for_slot(slot)
    }

    #[cfg(test)]
    /// Returns the pool where the preconf request is currently in.
    pub fn get_pool(&self, request_id: Uuid) -> Result<PoolType, PoolError> {
        let pool_inner = self.pool_inner.read();
        if pool_inner.pending.contains(request_id) {
            Ok(PoolType::Pending)
        } else if pool_inner.ready.contains(request_id) {
            Ok(PoolType::Ready)
        } else {
            Err(PoolError::PreconfRequestNotFound(request_id))
        }
    }

    pub fn blockspace_available(&self, slot: u64) -> BlockspaceAvailable {
        self.pool_inner.read().blockspace_issued.get(&slot).cloned().unwrap_or_default()
    }

    pub async fn calculate_gas_used(&self, tx: TxEnvelope) -> eyre::Result<u64> {
        self.validator.execution_client.gas_used(tx).await
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq)]
pub enum PoolType {
    Pending,
    Ready,
}
