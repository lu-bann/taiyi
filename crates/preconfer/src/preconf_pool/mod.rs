use std::{collections::HashMap, ops::Add, sync::Arc};

use alloy_consensus::{Transaction, TxEnvelope};
use alloy_primitives::{Address, U256};
use alloy_provider::utils::EIP1559_MIN_PRIORITY_FEE;
use parked::Parked;
use parking_lot::RwLock;
use pending::Pending;
use ready::Ready;
use reth_revm::primitives::EnvKzgSettings;
use taiyi_primitives::PreconfRequest;
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::{
    error::{PoolError, ValidationError},
    rpc_state::{get_account_state, AccountState},
    validator::{PreconfValidator, ValidationOutcome},
};

mod parked;
mod pending;
mod ready;

#[derive(Debug)]
pub struct PreconfPoolBuilder;

impl PreconfPoolBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(self, slot: u64) -> Arc<PreconfPool> {
        let validator = PreconfValidator::new(EIP1559_MIN_PRIORITY_FEE);
        Arc::new(PreconfPool::new(slot, validator))
    }
}

/// A pool that manages preconf requests.
/// This pool maintains the state of all preconf requests and stores them accordingly.
#[derive(Debug)]
pub struct PreconfPool {
    /// Pool inner
    pool_inner: RwLock<PreconfPoolInner>,
    /// Validator to validate preconf requests.
    validator: PreconfValidator,
    /// latest state fo the pool
    pool_state: PoolState,
}

impl PreconfPool {
    pub fn new(current_slot: u64, validator: PreconfValidator) -> Self {
        Self {
            pool_inner: RwLock::new(PreconfPoolInner {
                parked: Parked::new(),
                pending: Pending::new(),
                ready: Ready::new(current_slot),
                account_state: HashMap::new(),
            }),
            validator,
            pool_state: PoolState { current_slot },
        }
    }

    pub async fn request_inclusion(
        &self,
        preconf_request: PreconfRequest,
        request_id: Uuid,
        rpc_url: String,
    ) -> Result<PoolType, PoolError> {
        // Check if target slot is in the future
        let target_slot = preconf_request.target_slot;
        if target_slot <= self.pool_state.current_slot {
            return Err(PoolError::TargetSlotInPast);
        }
        // check for preconf tx
        if let Some(transaction) = &preconf_request.transaction {
            let sender = transaction
                .recover_signer()
                .map_err(|err| ValidationError::CustomError(err.to_string()))?;

            // fetch rpc state
            let rpc_state = get_account_state(rpc_url, sender).await.map_err(|_| {
                PoolError::Validation(ValidationError::AccountStateNotFound(sender))
            })?;

            // validate the preconf request
            let validation_outcome = self.validate(rpc_state, sender, transaction)?;

            match validation_outcome {
                ValidationOutcome::Valid { simulate } => {
                    if simulate {
                        // TODO: send the transaction to the simulator
                        self.insert_ready(request_id, preconf_request);
                        Ok(PoolType::Ready)
                    } else {
                        self.insert_pending(request_id, preconf_request);
                        Ok(PoolType::Pending)
                    }
                }
                ValidationOutcome::Invalid => Err(PoolError::InvalidPreconfTx(request_id)),
                _ => unimplemented!(),
            }
        } else {
            // TODO: check if blockspace is available in the pool
            self.insert_parked(request_id, preconf_request);
            Ok(PoolType::Parked)
        }
    }

    // NOTE: only checks account balance and nonce
    fn validate(
        &self,
        rpc_state: AccountState,
        sender: Address,
        transaction: &TxEnvelope,
    ) -> eyre::Result<ValidationOutcome, ValidationError> {
        // Priority fee check
        if let Some(p_fee) = transaction.max_priority_fee_per_gas() {
            if p_fee < self.validator.min_priority_fee {
                return Ok(ValidationOutcome::Invalid);
            }
        }

        let mut guard = self.pool_inner.write();
        let account_state = match guard.account_state.get(&sender) {
            Some(a_s) => a_s,
            None => &rpc_state,
        };

        let account_balance = account_state.balance.to::<u128>();
        let account_nonce = account_state.nonce;
        // Check if sender has enough balance to cover transaction cost
        // For EIP-1559 transactions: `max_fee_per_gas * gas_limit + tx_value`.
        let cost = transaction.max_fee_per_gas() * transaction.gas_limit() as u128
            + transaction.value().to::<u128>();

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

        // Apply state changes
        guard.account_state.insert(
            sender,
            AccountState { nonce: account_nonce + 1, balance: U256::from(account_balance - cost) },
        );
        drop(guard);

        // TODO: uncomment this once we have simulator ready
        // if target_slot == self.pool_state.current_slot + 1 {
        //     Ok(ValidationOutcome::Valid { simulate: true })
        // } else {
        //     Ok(ValidationOutcome::Valid { simulate: false })
        // }

        Ok(ValidationOutcome::Valid { simulate: false })
    }

    /// Returns all preconf requests that are ready to be executed in the next block.
    pub fn preconf_requests(&self) -> Result<Vec<PreconfRequest>, PoolError> {
        self.pool_inner.write().ready.fetch_preconf_requests()
    }

    /// Inserts a preconf request into the parked pool.
    fn insert_parked(&self, request_id: Uuid, preconf_request: PreconfRequest) {
        self.pool_inner.write().parked.insert(request_id, preconf_request);
    }

    /// Inserts a preconf request into the pending pool.
    fn insert_pending(&self, request_id: Uuid, preconf_request: PreconfRequest) {
        self.pool_inner.write().pending.insert(request_id, preconf_request);
    }

    /// Inserts a preconf request into the ready pool.
    fn insert_ready(&self, request_id: Uuid, preconf_request: PreconfRequest) {
        self.pool_inner.write().ready.insert_order(request_id, preconf_request);
    }

    /// Returns a preconf request from the parked pool.
    pub fn get_parked(&self, request_id: Uuid) -> Option<PreconfRequest> {
        self.pool_inner.read().parked.get(request_id)
    }

    /// Deletes a preconf request from the parked pool.
    pub fn delete_parked(&self, request_id: Uuid) -> Option<PreconfRequest> {
        self.pool_inner.write().parked.remove(request_id)
    }

    /// Returns the pool where the preconf request is currently in.
    pub fn get_pool(&self, request_id: Uuid) -> Result<PoolType, PoolError> {
        let pool_inner = self.pool_inner.read();
        if pool_inner.parked.contains(request_id) {
            Ok(PoolType::Parked)
        } else if pool_inner.pending.contains(request_id) {
            Ok(PoolType::Pending)
        } else if pool_inner.ready.contains(request_id) {
            Ok(PoolType::Ready)
        } else {
            Err(PoolError::PreconfRequestNotFound(request_id))
        }
    }

    pub fn move_pending_to_ready(&self, slot: u64) {
        self.pool_inner.write().move_pending_to_ready(slot);
    }
}

#[derive(Debug)]
pub struct PreconfPoolInner {
    /// Holds all parked preconf requests that depend on external changes from the sender:
    ///
    ///    - blocked by missing ancestor transaction (has nonce gaps)
    ///    - blocked by missing PreconfTx in preconf request
    parked: Parked,
    /// Holds all preconf requests that are ready to be included in the future slot.
    pending: Pending,
    /// Holds all preconf requests that are ready to be included in the next slot.
    ready: Ready,
    /// intermediate account state
    account_state: HashMap<Address, AccountState>,
}

impl PreconfPoolInner {
    pub fn move_pending_to_ready(&mut self, slot: u64) {
        let preconfs = match self.pending.remove_preconfs_for_slot(slot) {
            Ok(preconfs) => preconfs,
            Err(PoolError::SlotNotFound(slot)) => {
                info!("no preconf requests for slot {slot}");
                return;
            }
            Err(e) => {
                error!("failed to move pending to ready: {e}");
                return;
            }
        };
        for (preconf_hash, preconf_request) in preconfs {
            self.ready.insert_order(preconf_hash, preconf_request);
        }
        self.ready.update_slot(slot);
    }
}

#[derive(Debug, Clone)]
pub enum PoolType {
    Parked,
    Pending,
    Ready,
}

// TODO: add current base fee
/// The current state of the pool.
#[derive(Debug)]
pub struct PoolState {
    current_slot: u64,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use alloy_consensus::TxEnvelope;
    use alloy_network::{EthereumWallet, TransactionBuilder};
    use alloy_node_bindings::Anvil;
    use alloy_primitives::{U256, U64};
    use alloy_provider::{Provider, ProviderBuilder};
    use alloy_rpc_types::TransactionRequest;
    use alloy_signer_local::PrivateKeySigner;
    use tokio::time::sleep;
    use tracing::info;

    use crate::{
        preconf_pool::PreconfPoolBuilder, rpc_state::get_account_state,
        validator::ValidationOutcome,
    };

    #[tokio::test]
    async fn test_validate() -> eyre::Result<()> {
        tracing_subscriber::fmt::init();

        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();

        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&rpc_url).await?;
        let slot = provider.get_block_number().await?;
        let preconf_pool = PreconfPoolBuilder::new().build(slot);

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer);
        let rpc_state = get_account_state(rpc_url, *sender).await.unwrap();

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

        let validation_result = preconf_pool.validate(rpc_state, *sender, &transaction);
        info!("Validation result: {:?}", validation_result);

        assert!(validation_result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_low_balance_err() -> eyre::Result<()> {
        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();

        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&rpc_url).await?;
        let slot = provider.get_block_number().await?;
        let preconf_pool = PreconfPoolBuilder::new().build(slot);

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer);
        let rpc_state = get_account_state(rpc_url, *sender).await.unwrap();

        let fees = provider.estimate_eip1559_fees(None).await?;
        info!(
            "Fees: max_fee_per_gas: {:?}, max_priority_fee_per_gas: {:?}",
            fees.max_fee_per_gas, fees.max_priority_fee_per_gas
        );

        let transaction = TransactionRequest::default()
            .with_from(*sender)
            .with_value(U256::from(rpc_state.balance))
            .with_nonce(0)
            .with_gas_limit(21_0000)
            .with_to(*receiver)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(0)
            .build(&wallet)
            .await?;

        info!("Transaction built: {:?}", transaction);

        let validation_result = preconf_pool.validate(rpc_state, *sender, &transaction);
        info!("Validation result: {:?}", validation_result);

        assert!(validation_result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_nonce_too_high() -> eyre::Result<()> {
        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();

        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&rpc_url).await?;
        let slot = provider.get_block_number().await?;
        let preconf_pool = PreconfPoolBuilder::new().build(slot);

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer);
        let rpc_state = get_account_state(rpc_url, *sender).await.unwrap();

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

        let validation_result = preconf_pool.validate(rpc_state, *sender, &transaction);
        info!("Validation result: {:?}", validation_result);

        assert!(validation_result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_nonce_too_low() -> eyre::Result<()> {
        let anvil = Anvil::new().block_time(1).chain_id(0).spawn();
        let rpc_url = anvil.endpoint();

        let provider =
            ProviderBuilder::new().with_recommended_fillers().on_builtin(&rpc_url).await?;
        let slot = provider.get_block_number().await?;
        let preconf_pool = PreconfPoolBuilder::new().build(slot);

        let sender = anvil.addresses().first().unwrap();
        let receiver = anvil.addresses().last().unwrap();
        let sender_pk = anvil.keys().first().unwrap();
        let signer = PrivateKeySigner::from_signing_key(sender_pk.into());
        let wallet = EthereumWallet::from(signer);

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

        let rpc_state = get_account_state(rpc_url, *sender).await.unwrap();
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

        let validation_result = preconf_pool.validate(rpc_state, *sender, &transaction);
        info!("Validation result: {:?}", validation_result);

        assert!(validation_result.is_err());
        Ok(())
    }
}
