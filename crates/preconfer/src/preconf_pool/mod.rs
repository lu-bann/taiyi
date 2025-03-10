use std::{collections::HashMap, sync::Arc};

use alloy_consensus::{Transaction, TxEnvelope};
use alloy_eips::{eip1559::ETHEREUM_BLOCK_GAS_LIMIT, eip4844::MAX_BLOBS_PER_BLOCK};
use alloy_primitives::{Address, U256};
use parking_lot::RwLock;
use pending::Pending;
use ready::Ready;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use taiyi_primitives::PreconfRequest;
use uuid::Uuid;

use crate::{
    error::{PoolError, ValidationError},
    validator::PreconfValidator,
};

mod pending;
mod ready;

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
                ready: Ready::new(),
                blockspace_issued: HashMap::new(),
            }),
            validator,
            taiyi_escrow_address,
        }
    }

    pub async fn reserve_blockspace(
        &self,
        preconf_request: PreconfRequest,
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
        if blockspace_avail.gas_limit <= preconf_request.allocation.gas_limit
            || blockspace_avail.blobs <= preconf_request.allocation.blob_count
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

    pub async fn submit_transaction(
        &self,
        preconf_request: PreconfRequest,
        request_id: Uuid,
    ) -> Result<(), PoolError> {
        if preconf_request.transaction.is_some() {
            self.validate(&preconf_request).await?;
            // Move the request from pending to ready pool
            self.delete_pending(request_id);
            self.insert_ready(request_id, preconf_request);
            Ok(())
        } else {
            Err(PoolError::TransactionNotFound)
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

    // NOTE: only checks account balance and nonce
    async fn validate(
        &self,
        preconf_request: &PreconfRequest,
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
    pub fn fetch_pending(&self, slot: u64) -> Option<Vec<PreconfRequest>> {
        self.pool_inner.write().pending.fetch_preconf_requests_for_slot(slot)
    }

    /// Returns a preconf request from the pending pool.
    pub fn get_pending(&self, request_id: Uuid) -> Option<PreconfRequest> {
        self.pool_inner.read().pending.get(request_id)
    }

    /// Deletes a preconf request from the pending pool.
    pub fn delete_pending(&self, request_id: Uuid) -> Option<PreconfRequest> {
        self.pool_inner.write().pending.remove(request_id)
    }

    /// Inserts a preconf request into the pending pool.
    fn _insert_pending(&self, request_id: Uuid, preconf_request: PreconfRequest) {
        self.pool_inner.write().pending.insert(request_id, preconf_request);
    }

    /// Inserts a preconf request into the ready pool.
    fn insert_ready(&self, request_id: Uuid, preconf_request: PreconfRequest) {
        self.pool_inner.write().ready.insert(request_id, preconf_request);
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

#[derive(Debug)]
pub struct PreconfPoolInner {
    /// Stores requests without preconf transactions.
    pending: Pending,
    /// Stores requests with preconf transactions.
    ready: Ready,
    /// Blockspace issued for every slot is tracked here.
    blockspace_issued: HashMap<u64, BlockspaceAvailable>,
}

impl PreconfPoolInner {
    fn escrow_balance_diffs(&self, account: Address) -> Option<U256> {
        let pending_diff = self.pending.get_pending_diffs_for_account(account);
        let ready_diff = self.ready.get_pending_diffs_for_account(account);

        match (pending_diff, ready_diff) {
            (Some(pending_diff), Some(ready_diff)) => Some(pending_diff + ready_diff),
            (Some(pending_diff), None) => Some(pending_diff),
            (None, Some(ready_diff)) => Some(ready_diff),
            (None, None) => None,
        }
    }

    fn update_blockspace(&mut self, slot: u64, blockspace: BlockspaceAvailable) {
        self.blockspace_issued.insert(slot, blockspace);
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockspaceAvailable {
    pub gas_limit: u64,
    pub blobs: usize,
    pub num_of_constraints: u32,
}

impl Default for BlockspaceAvailable {
    fn default() -> Self {
        Self {
            gas_limit: ETHEREUM_BLOCK_GAS_LIMIT,
            blobs: MAX_BLOBS_PER_BLOCK,
            num_of_constraints: 256,
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq)]
pub enum PoolType {
    Pending,
    Ready,
}

#[allow(dead_code)]
// TODO: add intermidiate state for preconf requests
/// The current state of the pool.
#[derive(Debug)]
pub struct PoolState {
    current_slot: u64,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use alloy_consensus::{SidecarBuilder, SimpleCoder, TxEnvelope};
    use alloy_eips::{
        eip2718::Decodable2718,
        eip4844::{BYTES_PER_BLOB, DATA_GAS_PER_BLOB},
    };
    use alloy_network::{EthereumWallet, TransactionBuilder, TransactionBuilder4844};
    use alloy_node_bindings::Anvil;
    use alloy_primitives::{Address, U256};
    use alloy_provider::{Provider, ProviderBuilder};
    use alloy_rpc_types::TransactionRequest;
    use alloy_signer::Signer;
    use alloy_signer_local::PrivateKeySigner;
    use taiyi_primitives::{BlockspaceAllocation, PreconfRequest};
    use tokio::time::sleep;
    use tracing::info;
    use uuid::Uuid;

    use crate::preconf_pool::{PoolType, PreconfPoolBuilder};

    #[tokio::test]
    async fn test_add_remove_request() {
        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();
        let preconf_pool =
            PreconfPoolBuilder::new().build(rpc_url.parse().unwrap(), Address::default());

        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());

        let request = BlockspaceAllocation::default();
        let signature = signer.sign_hash(&request.digest()).await.unwrap();

        let mut preconf = PreconfRequest {
            allocation: request,
            alloc_sig: signature,
            transaction: None,
            signer: Some(Address::default()),
        };

        let request_id = Uuid::new_v4();
        preconf_pool._insert_pending(request_id, preconf.clone());
        assert_eq!(preconf_pool.get_pool(request_id).unwrap(), PoolType::Pending);

        // set transaction
        let raw_tx = alloy_primitives::hex::decode("02f86f0102843b9aca0085029e7822d68298f094d9e1459a7a482635700cbc20bbaf52d495ab9c9680841b55ba3ac080a0c199674fcb29f353693dd779c017823b954b3c69dffa3cd6b2a6ff7888798039a028ca912de909e7e6cdef9cdcaf24c54dd8c1032946dfa1d85c206b32a9064fe8").unwrap();
        let transaction = TxEnvelope::decode_2718(&mut raw_tx.as_slice()).unwrap();
        preconf.transaction = Some(transaction);
        preconf_pool.delete_pending(request_id);
        assert_eq!(preconf_pool.get_pending(request_id), None);

        // insert into ready pool
        preconf_pool.insert_ready(request_id, preconf.clone());
        assert!(preconf_pool.get_pool(request_id).is_ok());
        assert_eq!(preconf_pool.get_pool(request_id).unwrap(), PoolType::Ready);
    }

    #[tokio::test]
    async fn test_validate() -> eyre::Result<()> {
        tracing_subscriber::fmt::init();

        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();

        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&rpc_url).await?;
        let preconf_pool =
            PreconfPoolBuilder::new().build(rpc_url.parse().unwrap(), Address::default());

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer.clone());

        let fees = provider.estimate_eip1559_fees(None).await?;
        info!(
            "Fees: max_fee_per_gas: {:?}, max_priority_fee_per_gas: {:?}",
            fees.max_fee_per_gas, fees.max_priority_fee_per_gas
        );

        let transaction = TransactionRequest::default()
            .with_from(*sender)
            .with_value(U256::from(10))
            .with_nonce(0)
            .with_gas_limit(21_0000)
            .with_to(*receiver)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(0)
            .build(&wallet)
            .await?;

        info!("Transaction built: {:?}", transaction);
        let request = BlockspaceAllocation::default();
        let signature = signer.sign_hash(&request.digest()).await.unwrap();

        let preconf_request = PreconfRequest {
            allocation: request,
            alloc_sig: signature,
            transaction: Some(transaction),
            signer: Some(*sender),
        };
        let validation_result = preconf_pool.validate(&preconf_request).await;
        info!("Validation result: {:?}", validation_result);

        assert!(validation_result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_validate_4844_ok() -> eyre::Result<()> {
        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();

        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&rpc_url).await?;
        let preconf_pool =
            PreconfPoolBuilder::new().build(rpc_url.parse().unwrap(), Address::default());

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer.clone());

        let fees = provider.estimate_eip1559_fees(None).await?;
        info!(
            "Fees: max_fee_per_gas: {:?}, max_priority_fee_per_gas: {:?}",
            fees.max_fee_per_gas, fees.max_priority_fee_per_gas
        );

        // Create a sidecar with some data.
        let mut builder: SidecarBuilder<SimpleCoder> = SidecarBuilder::with_capacity(3);
        let data = vec![1u8; BYTES_PER_BLOB];
        builder.ingest(&data);
        builder.ingest(&data);
        let sidecar = builder.build()?;
        assert_eq!(sidecar.blobs.len(), 3);

        let gas_price = provider.get_gas_price().await?;

        let transaction = TransactionRequest::default()
            .with_from(*sender)
            .with_nonce(0)
            .with_to(*receiver)
            .with_gas_limit(3 * DATA_GAS_PER_BLOB)
            .with_max_fee_per_blob_gas(gas_price)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(0)
            .with_blob_sidecar(sidecar)
            .build(&wallet)
            .await?;

        info!("Transaction built: {:?}", transaction);

        let request = BlockspaceAllocation { blob_count: 3, ..Default::default() };
        let signature = signer.sign_hash(&request.digest()).await.unwrap();

        let preconf_request = PreconfRequest {
            allocation: request,
            alloc_sig: signature,
            transaction: Some(transaction.clone()),
            signer: Some(*sender),
        };
        let validation_result = preconf_pool.validate(&preconf_request).await;
        info!("Validation result: {:?}", validation_result);

        assert!(validation_result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_validate_4844_err_esceed_blob_count_limit() -> eyre::Result<()> {
        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();

        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&rpc_url).await?;
        let preconf_pool =
            PreconfPoolBuilder::new().build(rpc_url.parse().unwrap(), Address::default());

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer.clone());

        let fees = provider.estimate_eip1559_fees(None).await?;
        info!(
            "Fees: max_fee_per_gas: {:?}, max_priority_fee_per_gas: {:?}",
            fees.max_fee_per_gas, fees.max_priority_fee_per_gas
        );

        // Create a sidecar with some data.
        let mut builder: SidecarBuilder<SimpleCoder> = SidecarBuilder::with_capacity(3);
        let data = vec![1u8; BYTES_PER_BLOB];
        builder.ingest(&data);
        builder.ingest(&data);
        let sidecar = builder.build()?;
        assert_eq!(sidecar.blobs.len(), 3);

        let gas_price = provider.get_gas_price().await?;

        let transaction = TransactionRequest::default()
            .with_from(*sender)
            .with_nonce(0)
            .with_to(*receiver)
            .with_gas_limit(3 * DATA_GAS_PER_BLOB)
            .with_max_fee_per_blob_gas(gas_price)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(0)
            .with_blob_sidecar(sidecar.clone())
            .build(&wallet)
            .await?;

        info!("Transaction built: {:?}", transaction);

        let request = BlockspaceAllocation { blob_count: 1, ..Default::default() };
        let signature = signer.sign_hash(&request.digest()).await.unwrap();

        let preconf_request = PreconfRequest {
            allocation: request,
            alloc_sig: signature,
            transaction: Some(transaction.clone()),
            signer: Some(*sender),
        };
        let validation_result = preconf_pool.validate(&preconf_request).await;
        info!("Validation result: {:?}", validation_result);

        assert!(validation_result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_low_balance_err() -> eyre::Result<()> {
        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();

        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&rpc_url).await?;
        let preconf_pool =
            PreconfPoolBuilder::new().build(rpc_url.parse().unwrap(), Address::default());

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer.clone());

        let fees = provider.estimate_eip1559_fees(None).await?;
        info!(
            "Fees: max_fee_per_gas: {:?}, max_priority_fee_per_gas: {:?}",
            fees.max_fee_per_gas, fees.max_priority_fee_per_gas
        );

        let transaction = TransactionRequest::default()
            .with_from(*sender)
            .with_value(U256::MAX)
            .with_nonce(0)
            .with_gas_limit(21_0000)
            .with_to(*receiver)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(0)
            .build(&wallet)
            .await?;

        info!("Transaction built: {:?}", transaction);

        let request = BlockspaceAllocation::default();
        let signature = signer.sign_hash(&request.digest()).await.unwrap();
        let preconf_request = PreconfRequest {
            allocation: request,
            alloc_sig: signature,
            transaction: Some(transaction.clone()),
            signer: Some(*sender),
        };
        let validation_result = preconf_pool.validate(&preconf_request).await;
        assert!(validation_result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_nonce_too_high() -> eyre::Result<()> {
        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();

        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&rpc_url).await?;
        let preconf_pool =
            PreconfPoolBuilder::new().build(rpc_url.parse().unwrap(), Address::default());

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer.clone());

        let fees = provider.estimate_eip1559_fees(None).await?;
        info!(
            "Fees: max_fee_per_gas: {:?}, max_priority_fee_per_gas: {:?}",
            fees.max_fee_per_gas, fees.max_priority_fee_per_gas
        );

        let transaction = TransactionRequest::default()
            .with_from(*sender)
            .with_value(U256::from(100))
            .with_nonce(5)
            .with_gas_limit(21_0000)
            .with_to(*receiver)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(0)
            .build(&wallet)
            .await?;

        info!("Transaction built: {:?}", transaction);

        let request = BlockspaceAllocation::default();
        let signature = signer.sign_hash(&request.digest()).await.unwrap();

        let preconf_request = PreconfRequest {
            allocation: request,
            alloc_sig: signature,
            transaction: Some(transaction.clone()),
            signer: Some(*sender),
        };

        let validation_result = preconf_pool.validate(&preconf_request).await;
        assert!(validation_result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_nonce_too_low() -> eyre::Result<()> {
        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();

        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&rpc_url).await?;
        let preconf_pool =
            PreconfPoolBuilder::new().build(rpc_url.parse().unwrap(), Address::default());

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer.clone());

        let fees = provider.estimate_eip1559_fees(None).await?;
        let transaction = TransactionRequest::default()
            .with_from(*sender)
            .with_value(U256::from(10))
            .with_nonce(0)
            .with_gas_limit(21_0000)
            .with_to(*receiver)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(0);
        let pending_tx = provider.send_transaction(transaction).await?;
        info!("Pending transaction... {}", pending_tx.tx_hash());

        // Wait for the transaction to be included and get the receipt.
        let receipt = pending_tx.get_receipt().await?;

        info!(
            "Transaction included in block {}",
            receipt.block_number.expect("Failed to get block number")
        );
        // wait for 2*block_time duration
        sleep(Duration::from_secs(2)).await;

        let fees = provider.estimate_eip1559_fees(None).await?;
        info!(
            "Fees: max_fee_per_gas: {:?}, max_priority_fee_per_gas: {:?}",
            fees.max_fee_per_gas, fees.max_priority_fee_per_gas
        );

        let transaction = TransactionRequest::default()
            .with_from(*sender)
            .with_value(U256::from(100))
            .with_nonce(0)
            .with_gas_limit(21_0000)
            .with_to(*receiver)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(0)
            .build(&wallet)
            .await?;

        info!("Transaction built: {:?}", transaction);
        let request = BlockspaceAllocation::default();
        let signature = signer.sign_hash(&request.digest()).await.unwrap();
        let preconf_request = PreconfRequest {
            allocation: request,
            alloc_sig: signature,
            transaction: Some(transaction.clone()),
            signer: Some(*sender),
        };
        let validation_result = preconf_pool.validate(&preconf_request).await;
        assert!(validation_result.is_err());
        Ok(())
    }
}
