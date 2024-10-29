use std::{future::Future, sync::Arc, time::Duration};

use alloy_network::{Ethereum, EthereumWallet};
use alloy_primitives::{keccak256, Address, U256};
use alloy_provider::Provider;
use alloy_rpc_types_beacon::constants::BLS_DST_SIG;
use alloy_signer::{Signature as ECDSASignature, Signer};
use alloy_signer_local::PrivateKeySigner;
use alloy_transport::Transport;
use ethereum_consensus::{
    builder::compute_builder_domain,
    clock::{SlotStream, SystemTimeProvider},
    crypto::Signature,
    deneb::{compute_signing_root, Context},
};
use futures::StreamExt;
use taiyi_primitives::{
    AvailableSlotResponse, CancelPreconfRequest, CancelPreconfResponse, ConstraintsMessage,
    PreconfHash, PreconfRequest, PreconfResponse, PreconfStatus, PreconfStatusResponse, PreconfTx,
    SignedConstraintsMessage,
};
use tracing::{error, info};

use crate::{
    constraint_client::ConstraintClient,
    contract::preconf_reqs_to_constraints,
    error::{PoolError, RpcError, ValidationError},
    network_state::NetworkState,
    preconf_pool::{PoolState, PreconfPool, PreconfPoolBuilder},
    preconfer::Preconfer,
    pricer::PreconfPricer,
};

pub const SET_CONSTRAINTS_CUTOFF_NS: i64 = 8_000_000_000;
pub const SET_CONSTRAINTS_CUTOFF_NS_DELTA: i64 = -1_000_000_000;

#[derive(Clone)]
pub struct PreconfState<T, P, F> {
    preconfer: Preconfer<T, P, F>,
    constraint_client: ConstraintClient,
    network_state: NetworkState,
    preconf_pool: Arc<PreconfPool>,
    context: Context,
    bls_sk: blst::min_pk::SecretKey,
    ecdsa_signer: PrivateKeySigner,
    provider: P,
}

impl<T, P, F> PreconfState<T, P, F>
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone + 'static,
    F: PreconfPricer + Send + Sync + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        preconfer: Preconfer<T, P, F>,
        network_state: NetworkState,
        constraint_client: ConstraintClient,
        context: Context,
        bls_sk: blst::min_pk::SecretKey,
        ecdsa_signer: PrivateKeySigner,
        provider: P,
        owner: Address,
    ) -> Self {
        let slot = network_state.get_current_slot();
        let preconf_pool = PreconfPoolBuilder::new().build(slot, owner);
        Self {
            preconfer,
            constraint_client,
            network_state,
            preconf_pool,
            context,
            bls_sk,
            ecdsa_signer,
            provider,
        }
    }

    pub fn preconf_requests(&self) -> Result<Vec<PreconfRequest>, PoolError> {
        self.preconf_pool.preconf_requests()
    }

    async fn signed_constraints_message(
        &self,
        constraints_message: ConstraintsMessage,
    ) -> Result<SignedConstraintsMessage, RpcError> {
        let domain = compute_builder_domain(&self.context)
            .map_err(|e| RpcError::UnknownError(e.to_string()))?;
        let signing_root = compute_signing_root(&constraints_message, domain)
            .map_err(|e| RpcError::SignatureError(e.to_string()))?;
        let signature = self.bls_sk.sign(&signing_root.0, BLS_DST_SIG, &[]).to_bytes();
        let signature = Signature::try_from(signature.as_ref())
            .map_err(|e| RpcError::SignatureError(e.to_string()))?;

        Ok(SignedConstraintsMessage::new(constraints_message, signature))
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
                let slot = self.network_state.get_current_slot();
                let slot_start_timestamp = genesis_time + (slot * self.context.seconds_per_slot);
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

                let preconf_requests = self.preconf_requests()?;

                if preconf_requests.is_empty() {
                    continue;
                } else {
                    let wallet = EthereumWallet::new(self.ecdsa_signer.clone());
                    let constraint_message = preconf_reqs_to_constraints(
                        preconf_requests,
                        self.preconfer.taiyi_core_contract_addr(),
                        self.provider.clone(),
                        wallet,
                    )
                    .await?;
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

                self.preconf_pool.slot_updated(slot + 1);
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
                    preconf_pool.slot_updated(slot);
                }
            }
        }
    }

    pub async fn sign_tip_tx_signature(
        &self,
        tip_tx_signature: &ECDSASignature,
    ) -> Result<ECDSASignature, RpcError> {
        let message = tip_tx_signature.as_bytes().to_vec();
        let message = keccak256(&message);
        let signature = self
            .ecdsa_signer
            .sign_hash(&message)
            .await
            .map_err(|e| RpcError::SignatureError(e.to_string()))?;
        Ok(signature)
    }

    /// Send a preconf request to the preconfer
    ///
    /// Expected forms
    ///     - PreconfRequest without PreconfTx
    ///     - PreconfRequest with PreconfTx
    pub async fn send_preconf_request(
        &self,
        mut preconf_request: PreconfRequest,
    ) -> Result<PreconfResponse, RpcError> {
        let chain_id = self.get_chain_id().await?;
        let current_slot = self.network_state.get_current_slot();
        let preconf_hash = preconf_request.hash(U256::from(chain_id));
        let preconfer_signature =
            self.sign_tip_tx_signature(&preconf_request.tip_tx_signature).await?;
        preconf_request.preconfer_signature = Some(preconfer_signature);

        let preconf_req_hash = preconf_request.preconf_req_hash(U256::from(chain_id)).ok_or(
            RpcError::UnknownError(format!(
                "Failed to get preconf req hash from {preconf_request:?}",
            )),
        )?;

        self.preconfer
            .verify_escrow_balance_and_calc_fee(&preconf_request.tip_tx.from, &preconf_request)
            .await?;

        match self.preconf_pool.request_inclusion(
            preconf_request.clone(),
            current_slot,
            U256::from(chain_id),
        ) {
            Ok(PoolState::Ready) | Ok(PoolState::Pending) => {
                let preconf_req_signature = self
                    .ecdsa_signer
                    .sign_hash(&preconf_req_hash)
                    .await
                    .map_err(|err| RpcError::SignatureError(err.to_string()))?;
                preconf_request.preconf_req_signature = Some(preconf_req_signature);

                Ok(PreconfResponse::success(
                    preconf_hash,
                    preconfer_signature,
                    Some(preconf_req_signature),
                ))
            }
            Ok(PoolState::Parked) => {
                Ok(PreconfResponse::success(preconf_hash, preconfer_signature, None))
            }
            Err(e) => Err(RpcError::PoolError(e)),
        }
    }

    pub async fn cancel_preconf_request(
        &self,
        _cancel_preconf_request: CancelPreconfRequest,
    ) -> Result<CancelPreconfResponse, PoolError> {
        unimplemented!()
    }

    pub async fn send_preconf_tx_request(
        &self,
        preconf_req_hash: PreconfHash,
        preconf_tx: PreconfTx,
    ) -> Result<PreconfResponse, RpcError> {
        let mut preconf_request = self
            .preconf_pool
            .get_parked(&preconf_req_hash)
            .ok_or(PoolError::PreconfRequestNotFound(preconf_req_hash))?;
        let current_slot = self.network_state.get_current_slot();
        let chain_id = self.get_chain_id().await?;
        if preconf_request.preconf_tx.is_some() {
            return Err(RpcError::PreconfTxAlreadySet(preconf_req_hash));
        }
        preconf_request.preconf_tx = Some(preconf_tx.clone());

        match self.preconf_pool.request_inclusion(
            preconf_request.clone(),
            current_slot,
            U256::from(chain_id),
        ) {
            Ok(PoolState::Ready) | Ok(PoolState::Pending) => {
                let preconf_req_signature = self
                    .ecdsa_signer
                    .sign_hash(&preconf_req_hash)
                    .await
                    .map_err(|err| RpcError::SignatureError(err.to_string()))?;
                preconf_request.preconf_req_signature = Some(preconf_req_signature);

                Ok(PreconfResponse::success(
                    preconf_req_hash,
                    preconf_request.preconfer_signature.expect("preconfer signature"),
                    Some(preconf_req_signature),
                ))
            }
            Err(PoolError::InvalidPreconfTx(_)) => {
                self.preconf_pool.delete_parked(&preconf_req_hash);
                self.preconfer.taiyi_core_contract.exhaust(preconf_request.into()).call().await?;
                Err(RpcError::PreconfRequestError("Invalid preconf tx".to_string()))
            }
            _ => Err(RpcError::UnknownError("Invalid pool state".to_string())),
        }
    }

    pub async fn check_preconf_request_status(
        &self,
        preconf_hash: PreconfHash,
    ) -> Result<PreconfStatusResponse, PoolError> {
        let pool = self.preconf_pool.get_pool(&preconf_hash)?;
        let status = match pool {
            PoolState::Parked => PreconfStatus::Pending,
            PoolState::Pending => PreconfStatus::Pending,
            PoolState::Ready => PreconfStatus::Accepted,
        };
        Ok(PreconfStatusResponse { status })
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
    async fn _validate_tx_request(
        &self,
        _tx: &PreconfTx,
        _order: &PreconfRequest,
    ) -> Result<(), ValidationError> {
        // let sender = order.tip_tx.from;
        // Vaiidate the chain id
        // TODO: check wheter we should introduce chain id
        // if let Some(chainid) = tx.chain_id() {
        //     if chainid
        //         != self.get_chain_id().await.map_err(|e| {
        //             ValidationError::Internal(format!("Failed to get chain id: {e:?}"))
        //         })?
        //     {
        //         return Err(ValidationError::ChainIdMismatch);
        //     }
        // }

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

        // if tx.gas_limit() > order.tip_tx.gas_limit {
        //     return Err(ValidationError::GasLimitTooHigh);
        // }

        // let (prev_balance, prev_nonce) = self
        //     .preconf_pool
        //     .read()
        //     .prioritized_orderpool
        //     .intermediate_state
        //     .get(&sender)
        //     .cloned()
        //     .unwrap_or_default();

        // let account_state_opt: Option<AccountState>;
        // {
        //     account_state_opt = self
        //         .preconf_pool
        //         .read()
        //         .prioritized_orderpool
        //         .canonical_state
        //         .get(&sender)
        //         .copied();
        // }

        // let mut account_state = match account_state_opt {
        //     Some(state) => state,
        //     None => {
        //         let state = get_account_state(self.execution_client_url.clone(), sender)
        //             .await
        //             .map_err(|e| {
        //                 ValidationError::Internal(format!("Failed to get account state: {e:?}"))
        //             })?;
        //         {
        //             self.preconf_pool
        //                 .write()
        //                 .prioritized_orderpool
        //                 .canonical_state
        //                 .insert(sender, state);
        //         }
        //         state
        //     }
        // };
        // // apply the nonce and balance diff
        // account_state.nonce += prev_nonce;
        // account_state.balance -= prev_balance;

        // let nonce = order.nonce();

        // // order can't be included
        // if account_state.nonce > nonce.to() {
        //     return Err(ValidationError::NonceTooLow(account_state.nonce, nonce.to()));
        // }

        // if account_state.nonce < nonce.to() {
        //     return Err(ValidationError::NonceTooHigh(account_state.nonce, nonce.to()));
        // }

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

    async fn get_chain_id(&self) -> Result<u64, RpcError> {
        self.provider.get_chain_id().await.map_err(|e| RpcError::UnknownError(e.to_string()))
    }
}
