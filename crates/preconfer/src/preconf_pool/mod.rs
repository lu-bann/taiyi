use std::{collections::HashMap, sync::Arc};

use alloy_consensus::{Transaction, TxEnvelope};
use alloy_primitives::{Address, U256};
use inner::BlockspaceAvailable;
use parking_lot::RwLock;
use pending::Pending;
use ready::Ready;
use reqwest::Url;
use taiyi_primitives::{PreconfRequest, PreconfRequestTypeA, PreconfRequestTypeB};
use uuid::Uuid;

use crate::{
    error::{PoolError, ValidationError},
    preconf_pool::inner::PreconfPoolInner,
    validator::PreconfValidator,
};

mod inner;
mod pending;
mod ready;
#[cfg(test)]
mod tests;

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
        }
    }

    pub async fn reserve_blockspace(
        &self,
        preconf_request: PreconfRequestTypeB,
    ) -> Result<Uuid, PoolError> {
        // check if the sender has enough balance to lock the deposit
        self.has_enough_balance(
            preconf_request.signer.expect("signer"),
            preconf_request.allocation.deposit,
        )
        .await?;

        let mut pool_inner = self.pool_inner.write();

        let mut blockspace_avail =
            match pool_inner.blockspace_issued.get(&preconf_request.target_slot()) {
                Some(space) => space.clone(),
                None => BlockspaceAvailable::default(),
            };

        // Verify that we have enough space
        if blockspace_avail.gas_limit < preconf_request.allocation.gas_limit
            || blockspace_avail.blobs < preconf_request.allocation.blob_count
        {
            return Err(PoolError::BlockspaceNotAvailable);
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
    ) -> Result<PreconfRequest, PoolError> {
        match preconf_request {
            PreconfRequest::TypeA(preconf_request) => {
                self.validate_typea(&preconf_request).await?;
                Ok(self.insert_ready(request_id, PreconfRequest::TypeA(preconf_request)))
            }
            PreconfRequest::TypeB(preconf_request) => {
                if preconf_request.transaction.is_some() {
                    self.validate_typeb(&preconf_request).await?;
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
        deposit: U256,
    ) -> Result<(), PoolError> {
        let pending_diffs_for_account = self.pool_inner.read().escrow_balance_diffs(account);
        let escrow_balance =
            self.validator.execution_client.balance_of(account, self.taiyi_escrow_address).await;

        match escrow_balance {
            Ok(balance) => {
                let effective_balance =
                    balance - U256::from(pending_diffs_for_account.unwrap_or_default());
                if effective_balance < deposit {
                    Err(PoolError::InsufficientEscrowBalance(effective_balance, deposit))
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
    ) -> eyre::Result<(), ValidationError> {
        let signer = match preconf_request.signer() {
            Some(signer) => signer,
            None => return Err(ValidationError::SignerNotFound),
        };

        let account_state = self
            .validator
            .execution_client
            .get_account_state(signer)
            .await
            .map_err(|_| ValidationError::AccountStateNotFound(signer))?;

        let account_balance = account_state.balance;
        let account_nonce = account_state.nonce;

        // Tip transaction must be an ETH transfer
        if !preconf_request.tip_transaction.is_eip1559() {
            return Err(ValidationError::InvalidTipTransaction);
        }

        // TODO: check tip
        // NOTE: requires a price oracle to check the tip

        // Nonce check
        let preconf_tx_nonce = preconf_request.preconf_tx.nonce();
        let tip_tx_nonce = preconf_request.tip_transaction.nonce();

        // Check for continuity of nonce
        // The nonce of the preconf transaction must be one more than the nonce of the tip transaction
        if preconf_tx_nonce != tip_tx_nonce + 1 {
            return Err(ValidationError::InvalidNonceSequence(tip_tx_nonce, preconf_tx_nonce));
        }

        let nonce = preconf_tx_nonce.min(tip_tx_nonce);
        if nonce > account_nonce {
            return Err(ValidationError::NonceTooHigh(account_nonce, nonce));
        }

        if nonce < account_nonce {
            return Err(ValidationError::NonceTooLow(account_nonce, nonce));
        }

        // Balance check
        let total_value =
            preconf_request.preconf_tx.value() + preconf_request.tip_transaction.value();
        if account_balance < total_value {
            return Err(ValidationError::LowBalance(total_value - account_balance));
        }

        // heavy blob tx validation
        if preconf_request.preconf_tx.is_eip4844() {
            let transaction = preconf_request
                .preconf_tx
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

        Ok(())
    }

    // NOTE: only checks account balance and nonce
    async fn validate_typeb(
        &self,
        preconf_request: &PreconfRequestTypeB,
    ) -> eyre::Result<(), ValidationError> {
        let signer = match preconf_request.signer {
            Some(signer) => signer,
            None => return Err(ValidationError::SignerNotFound),
        };
        let transaction = match preconf_request.transaction.clone() {
            Some(transaction) => transaction,
            None => return Err(ValidationError::TransactionNotFound),
        };

        let account_state = self
            .validator
            .execution_client
            .get_account_state(signer)
            .await
            .map_err(|_| ValidationError::AccountStateNotFound(signer))?;

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
        if nonce > account_nonce {
            return Err(ValidationError::NonceTooHigh(account_nonce, nonce));
        }

        if nonce < account_nonce {
            return Err(ValidationError::NonceTooLow(account_nonce, nonce));
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

        Ok(())
    }

    /// Returns preconf requests in pending pool for a given slot.
    pub fn fetch_pending(&self, slot: u64) -> Option<Vec<PreconfRequestTypeB>> {
        self.pool_inner.write().pending.fetch_preconf_requests_for_slot(slot)
    }

    /// Returns a preconf request from the pending pool.
    pub fn get_pending(&self, request_id: Uuid) -> Option<PreconfRequestTypeB> {
        self.pool_inner.read().pending.get(request_id)
    }

    /// Deletes a preconf request from the pending pool.
    pub fn delete_pending(&self, request_id: Uuid) -> Option<PreconfRequestTypeB> {
        self.pool_inner.write().pending.remove(request_id)
    }

    /// Inserts a preconf request into the pending pool.
    fn _insert_pending(&self, request_id: Uuid, preconf_request: PreconfRequestTypeB) {
        self.pool_inner.write().pending.insert(request_id, preconf_request);
    }

    /// Inserts a preconf request into the ready sub-pool.
    fn insert_ready(&self, request_id: Uuid, preconf_request: PreconfRequest) -> PreconfRequest {
        self.pool_inner.write().ready.insert(request_id, preconf_request)
    }

    /// Returns preconf requests in ready pool.
    pub fn ready_requests(&self, slot: u64) -> Result<Vec<PreconfRequest>, PoolError> {
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
