use alloy_consensus::{Transaction, TxEnvelope};
use alloy_network::Ethereum;
use alloy_primitives::U256;
use alloy_provider::Provider;
use alloy_rlp::Encodable;
use alloy_rpc_types_beacon::{BlsPublicKey, BlsSignature};
use alloy_transport::Transport;
use cb_pbs::BuilderApiState;
use ethereum_consensus::clock::{SlotStream, SystemTimeProvider};
use ethereum_consensus::crypto::Signature;
use ethereum_consensus::{
    builder::compute_builder_domain,
    deneb::{compute_signing_root, Context},
};
use futures::StreamExt;
use luban_primitives::{
    AvailableSlotResponse, CancelPreconfRequest, CancelPreconfResponse, ConstraintsMessage,
    PreconfHash, PreconfRequest, PreconfResponse, PreconfStatus, PreconfStatusResponse,
    SignedConstraintsMessage,
};
use parking_lot::RwLock;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

use crate::preconf_pool::PreconfPool;
use crate::{
    constraint_client::ConstraintClient,
    error::{OrderPoolError, ProposerError, RpcError, ValidationError},
    network_state::NetworkState,
    preconfer::{Preconfer, TipTx},
    pricer::PreconfPricer,
    rpc_state::{get_account_state, AccountState},
    signer_client::SignerClient,
};

pub const MAX_COMMITMENTS_PER_SLOT: usize = 1024 * 1024;
pub const SET_CONSTRAINTS_CUTOFF_NS: i64 = 8_000_000_000;
pub const SET_CONSTRAINTS_CUTOFF_NS_DELTA: i64 = -1_000_000_000;

#[derive(Clone)]
pub struct PreconfState<T, P, F> {
    rpc_url: String,
    preconfer: Preconfer<T, P, F>,
    signer_client: SignerClient,
    constraint_client: ConstraintClient,
    network_state: NetworkState,
    preconf_pool: Arc<RwLock<PreconfPool>>,
    context: Context,
}

impl<
        T: Clone + Send + Sync + 'static,
        P: Clone + Send + Sync + 'static,
        F: Clone + Send + Sync + 'static,
    > BuilderApiState for PreconfState<T, P, F>
{
}

impl<T, P, F> PreconfState<T, P, F>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone + 'static,
    F: PreconfPricer + Send + Sync + 'static,
{
    pub async fn new(
        rpc_url: String,
        preconfer: Preconfer<T, P, F>,
        network_state: NetworkState,
        signer_client: SignerClient,
        constraint_client: ConstraintClient,
        context: Context,
    ) -> Self {
        Self {
            rpc_url,
            preconfer,
            signer_client,
            constraint_client,
            network_state,
            preconf_pool: Arc::new(RwLock::new(PreconfPool::new())),
            context,
        }
    }

    fn key_for_slot(&self, slot: u64) -> Result<BlsPublicKey, ProposerError> {
        Ok(self
            .network_state
            .propser_duty_for_slot(slot)
            .ok_or(ProposerError::ProposerDutyNotFound)?
            .pubkey)
    }

    pub fn constraints(&self) -> Result<ConstraintsMessage, OrderPoolError> {
        self.preconf_pool
            .write()
            .prioritized_orderpool
            .constraints()
    }

    async fn signed_constraints_message(
        &self,
        constraints_message: ConstraintsMessage,
    ) -> Result<SignedConstraintsMessage, RpcError> {
        let domain = compute_builder_domain(&self.context)
            .map_err(|e| RpcError::UnknownError(e.to_string()))?;
        let signing_root = compute_signing_root(&constraints_message, domain)
            .map_err(|e| RpcError::UnknownError(e.to_string()))?;

        let consensus_key = self.key_for_slot(constraints_message.slot)?;
        let proxy_key = self
            .signer_client
            .proxy_key_map
            .get(&consensus_key)
            .ok_or(RpcError::ProposerError(ProposerError::ProxyKeyNotFound))?;

        let signature = self
            .signer_client
            .sign_message(signing_root.into(), *proxy_key)
            .await?;
        let signature = Signature::try_from(signature.as_ref())
            .map_err(|e| RpcError::UnknownError(e.to_string()))?;

        Ok(SignedConstraintsMessage::new(
            constraints_message,
            signature,
        ))
    }

    #[allow(unreachable_code)]
    pub fn spawn_constraint_submitter(self) -> impl Future<Output = eyre::Result<()>> {
        let constraint_client = self.constraint_client.clone();
        let genesis_time = match self.context.genesis_time() {
            Ok(genesis_time) => genesis_time,
            Err(_) => self.context.min_genesis_time + self.context.genesis_delay,
        };

        async move {
            loop {
                let slot_start_timestamp = genesis_time
                    + (self.network_state.get_current_slot() * self.context.seconds_per_slot);
                let submit_start_time = slot_start_timestamp as i64 * 1_000_000_000
                    + SET_CONSTRAINTS_CUTOFF_NS
                    + SET_CONSTRAINTS_CUTOFF_NS_DELTA;
                let sleep_duration = submit_start_time
                    - time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64;
                if sleep_duration.is_positive() {
                    tokio::time::sleep(Duration::from_nanos(
                        sleep_duration.try_into().expect("positive sleep duration"),
                    ))
                    .await;
                }

                let constraint_message = self.constraints()?;
                if constraint_message.is_empty() {
                    continue;
                } else {
                    info!(
                        "Sending {} constraints message with slot: {}",
                        constraint_message.len(),
                        constraint_message.slot
                    );
                    let signed_constraints_message = self
                        .signed_constraints_message(constraint_message)
                        .await
                        .expect("signed constraints");
                    let max_retries = 5;
                    let mut i = 0;

                    'submit: while let Err(e) = constraint_client
                        .send_set_constraints(signed_constraints_message.clone())
                        .await
                    {
                        error!(err = ?e, "Error submitting constraints to relay, retrying...");
                        i += 1;
                        if i >= max_retries {
                            error!("Max retries reached while submitting to MEV-Boost");
                            break 'submit;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
            Ok(())
        }
    }

    pub fn spawn_orderpool_cleaner(
        &self,
        mut slot_stream: SlotStream<SystemTimeProvider>,
    ) -> impl Future<Output = ()> {
        let preconf_pool = self.preconf_pool.clone();
        async move {
            loop {
                if let Some(slot) = slot_stream.next().await {
                    preconf_pool.write().slot_updated(slot);
                }
            }
        }
    }

    pub async fn sign_init_signature(
        &self,
        preconf_request: &PreconfRequest,
    ) -> Result<BlsSignature, RpcError> {
        let consensus_key = self.key_for_slot(preconf_request.preconf_conditions.slot)?;
        let proxy_key = self
            .signer_client
            .proxy_key_map
            .get(&consensus_key)
            .ok_or(RpcError::ProposerError(ProposerError::ProxyKeyNotFound))?;
        Ok(self
            .signer_client
            .sign_preconf_request(preconf_request, *proxy_key)
            .await?)
    }

    /// Send a preconf request to the preconfer
    ///
    /// Stores the preconf request in the Orderpool until the preconf tx is received
    pub async fn send_preconf_request(
        &self,
        mut preconf_request: PreconfRequest,
    ) -> Result<PreconfResponse, RpcError> {
        let preconf_hash = self
            .preconf_pool
            .read()
            .prevalidate_req(self.signer_client.chain_id.to(), &preconf_request)?;
        let preconfer_signature = self.sign_init_signature(&preconf_request).await?;

        preconf_request.init_signature = preconfer_signature;
        match self
            .preconfer
            .verify_escrow_balance_and_calc_fee(&preconf_request.tip_tx.from, &preconf_request)
            .await
        {
            Ok(_) => {}
            Err(e) => return Err(RpcError::UnknownError(format!("validate error {e:?}"))),
        }

        self.preconf_pool
            .write()
            .orderpool
            .insert(preconf_hash, preconf_request.clone());

        Ok(PreconfResponse::success(preconf_hash, preconfer_signature))
    }

    pub async fn cancel_preconf_request(
        &self,
        cancel_preconf_request: CancelPreconfRequest,
    ) -> Result<CancelPreconfResponse, OrderPoolError> {
        if self
            .preconf_pool
            .write()
            .orderpool
            .delete(&cancel_preconf_request.preconf_hash)
            .is_some()
        {
            Ok(CancelPreconfResponse {})
        } else {
            Err(OrderPoolError::PreconfRequestNotFound(
                cancel_preconf_request.preconf_hash,
            ))
        }
    }

    pub async fn send_preconf_tx_request(
        &self,
        preconf_req_hash: PreconfHash,
        preconf_tx: TxEnvelope,
    ) -> Result<(), RpcError> {
        let mut preconf_request = self
            .preconf_pool
            .read()
            .orderpool
            .get(&preconf_req_hash)
            .ok_or(OrderPoolError::PreconfRequestNotFound(preconf_req_hash))?;

        // User is expected to send the tx calldata in the slot specified in the preconf request.
        let target_slot = preconf_request.preconf_conditions.slot;
        let current_slot = self
            .preconf_pool
            .read()
            .prioritized_orderpool
            .slot
            .ok_or(OrderPoolError::PrioritizedOrderPoolNotInitialized)?;
        if target_slot != current_slot {
            return Err(RpcError::SlotMismatch(target_slot, current_slot));
        }

        if preconf_request.preconf_tx.is_some() {
            return Err(RpcError::PreconfTxAlreadySet(preconf_req_hash));
        }
        let mut tx = Vec::new();
        preconf_tx.encode(&mut tx);
        preconf_request.preconf_tx = Some(tx);

        self.preconf_pool
            .write()
            .orderpool
            .insert(preconf_req_hash, preconf_request.clone());

        // Call exhuast if validate_tx_request fails
        if self
            .validate_tx_request(&preconf_tx, &preconf_request)
            .await
            .is_err()
        {
            self.preconfer
                .luban_core_contract
                .exhaust(
                    TipTx {
                        gasLimit: preconf_request.tip_tx.gas_limit,
                        from: preconf_request.tip_tx.from,
                        to: preconf_request.tip_tx.to,
                        prePay: preconf_request.tip_tx.pre_pay,
                        afterPay: preconf_request.tip_tx.after_pay,
                        nonce: preconf_request.tip_tx.nonce,
                    },
                    preconf_request.init_signature.into(),
                    preconf_request.preconfer_signature,
                )
                .call()
                .await?;
        } else {
            self.preconf_pool
                .write()
                .prioritized_orderpool
                .insert_order(preconf_req_hash, preconf_request);
            self.preconf_pool
                .write()
                .orderpool
                .delete(&preconf_req_hash);
        }

        Ok(())
    }

    // TODO: change this
    pub async fn check_preconf_request_status(
        &self,
        preconf_tx_hash: PreconfHash,
    ) -> Result<PreconfStatusResponse, OrderPoolError> {
        match self.preconf_pool.read().orderpool.get(&preconf_tx_hash) {
            Some(preconf_request) => Ok(PreconfStatusResponse {
                status: PreconfStatus::Accepted,
                data: preconf_request,
            }),
            None => Err(OrderPoolError::PreconfRequestNotFound(preconf_tx_hash)),
        }
    }

    pub async fn available_slot(&self) -> Result<AvailableSlotResponse, RpcError> {
        Ok(AvailableSlotResponse {
            current_slot: self.network_state.get_current_slot(),
            current_epoch: self.network_state.get_current_epoch(),
            available_slots: self.network_state.get_proposer_duties(),
        })
    }

    // TDOD: validate all fields
    // After validating the tx req, update the state in insert_order function
    // NOTE: If validation fails, call exhaust
    async fn validate_tx_request(
        &self,
        tx: &TxEnvelope,
        order: &PreconfRequest,
    ) -> Result<(), ValidationError> {
        let sender = order.tip_tx.from;
        // Vaiidate the chain id
        if let Some(chainid) = tx.chain_id() {
            if chainid != self.signer_client.chain_id.to::<u64>() {
                return Err(ValidationError::ChainIdMismatch);
            }
        }

        // Check if the transaction size exceeds the maximum
        // if tx.inner_length() > MAX_TRANSACTION_SIZE {
        //     return Err(ValidationError::TransactionSizeTooHigh);
        // }
        // Check if the transaction is a contract creation and the init code size exceeds the maximum
        // if tx.is_create() {
        //     let code_size = tx.code_size().expect("no code size");
        //     if code_size > MAX_CODE_SIZE {
        //         return Err(ValidationError::CodeSizeTooLarge);
        //     }
        // }

        let gas_limit = get_tx_gas_limit(tx);
        if U256::from(gas_limit) > order.tip_tx.gas_limit {
            return Err(ValidationError::GasLimitTooHigh);
        }

        let (prev_balance, prev_nonce) = self
            .preconf_pool
            .read()
            .prioritized_orderpool
            .intermediate_state
            .get(&sender)
            .cloned()
            .unwrap_or_default();

        let account_state_opt: Option<AccountState>;
        {
            account_state_opt = self
                .preconf_pool
                .read()
                .prioritized_orderpool
                .canonical_state
                .get(&sender)
                .copied();
        }

        let mut account_state = match account_state_opt {
            Some(state) => state,
            None => {
                let state = get_account_state(self.rpc_url.clone(), sender)
                    .await
                    .map_err(|e| {
                        ValidationError::Internal(format!("Failed to get account state: {e:?}"))
                    })?;
                {
                    self.preconf_pool
                        .write()
                        .prioritized_orderpool
                        .canonical_state
                        .insert(sender, state);
                }
                state
            }
        };
        // apply the nonce and balance diff
        account_state.nonce += prev_nonce;
        account_state.balance -= prev_balance;

        let nonce = order.nonce();

        // order can't be included
        if account_state.nonce > nonce.to() {
            return Err(ValidationError::NonceTooLow(
                account_state.nonce,
                nonce.to(),
            ));
        }

        if account_state.nonce < nonce.to() {
            return Err(ValidationError::NonceTooHigh(
                account_state.nonce,
                nonce.to(),
            ));
        }

        // Check EIP-4844-specific limits
        // if let Some(transaction) = tx.as_eip4844() {
        //     if self.priortised_orderpool.read().blob_count() >= MAX_BLOBS_PER_BLOCK {
        //         return Err(ValidationError::Eip4844Limit);
        //     }

        //     let PooledTransactionsElement::BlobTransaction(ref blob_transaction) = tx.deref()
        //     else {
        //         unreachable!("EIP-4844 transaction should be a blob transaction")
        //     };

        //     // Calculate max possible increase in blob basefee
        //     let max_blob_basefee = calculate_max_basefee(self.blob_basefee, slot_diff)
        //         .ok_or(ValidationError::MaxBaseFeeCalcOverflow)?;

        //     debug!(%max_blob_basefee, blob_basefee = blob_transaction.transaction.max_fee_per_blob_gas, "Validating blob basefee");
        //     if blob_transaction.transaction.max_fee_per_blob_gas < max_blob_basefee {
        //         return Err(ValidationError::BlobBaseFeeTooLow(max_blob_basefee));
        //     }

        //     // Validate blob against KZG settings
        //     transaction.validate_blob(&blob_transaction.sidecar, self.kzg_settings.get())?;
        // }

        Ok(())
    }
}

fn get_tx_gas_limit(tx: &TxEnvelope) -> u128 {
    match tx {
        TxEnvelope::Legacy(t) => t.tx().gas_limit,
        TxEnvelope::Eip2930(t) => t.tx().gas_limit,
        TxEnvelope::Eip1559(t) => t.tx().gas_limit,
        TxEnvelope::Eip4844(t) => t.tx().tx().gas_limit,
        _ => panic!("not implemted"),
    }
}
