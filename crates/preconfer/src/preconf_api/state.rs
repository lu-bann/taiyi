use std::{future::Future, sync::Arc, time::Duration};

use alloy_consensus::TxEnvelope;
use alloy_network::{Ethereum, EthereumWallet};
use alloy_primitives::keccak256;
use alloy_provider::Provider;
use alloy_signer::{Signature as ECDSASignature, Signer};
use alloy_signer_local::PrivateKeySigner;
use alloy_transport::Transport;
use ethereum_consensus::{
    altair::genesis,
    clock::{from_system_time, Clock},
    deneb::Context,
};
use futures::StreamExt;
use reth_primitives::PooledTransactionsElement;
use taiyi_primitives::{
    CancelPreconfRequest, CancelPreconfResponse, ConstraintsMessage, PreconfRequest,
    PreconfResponse, PreconfStatus, PreconfStatusResponse,
};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{
    constraint_client::{preconf_reqs_to_constraints, ConstraintClient},
    error::{PoolError, RpcError},
    network_state::NetworkState,
    preconf_pool::{PoolType, PreconfPool, PreconfPoolBuilder},
    pricer::PreconfPricer,
};

pub const SET_CONSTRAINTS_CUTOFF_NS: i64 = 8_000_000_000;
pub const SET_CONSTRAINTS_CUTOFF_NS_DELTA: i64 = -1_000_000_000;

#[derive(Clone)]
pub struct PreconfState {
    constraint_client: ConstraintClient,
    network_state: NetworkState,
    preconf_pool: Arc<PreconfPool>,
    context: Context,
    bls_sk: blst::min_pk::SecretKey,
    ecdsa_signer: PrivateKeySigner,
}

impl PreconfState {
    pub async fn new(
        network_state: NetworkState,
        constraint_client: ConstraintClient,
        context: Context,
        bls_sk: blst::min_pk::SecretKey,
        ecdsa_signer: PrivateKeySigner,
    ) -> Self {
        let slot = network_state.get_current_slot();
        let preconf_pool = PreconfPoolBuilder::new().build(slot);
        Self { constraint_client, network_state, preconf_pool, context, bls_sk, ecdsa_signer }
    }

    pub fn preconf_requests(&self) -> Result<Vec<PreconfRequest>, PoolError> {
        self.preconf_pool.preconf_requests()
    }

    #[allow(unreachable_code)]
    pub fn spawn_constraint_submitter(self) -> impl Future<Output = eyre::Result<()>> {
        let constraint_client = self.constraint_client.clone();
        let genesis_time = match self.context.genesis_time() {
            Ok(genesis_time) => genesis_time,
            Err(_) => self.context.min_genesis_time + self.context.genesis_delay,
        };

        async move {
            // wait for 3 seconds to let the first network state slot to be initialized
            // this is a temporary solution to let the first network state slot to be initialized
            tokio::time::sleep(Duration::from_secs(3)).await;
            let mut last_slot = self.network_state.get_current_slot();
            loop {
                let slot = self.network_state.get_current_slot();
                debug!("current slot: {slot}, last slot: {last_slot}");
                if slot == last_slot {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                let slot_start_timestamp =
                    (genesis_time + (slot * self.context.seconds_per_slot)) * 1_000_000_000;
                let submit_start_time = slot_start_timestamp as i64
                    + SET_CONSTRAINTS_CUTOFF_NS
                    + SET_CONSTRAINTS_CUTOFF_NS_DELTA;
                let sleep_duration = submit_start_time
                    - time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64;
                info!(
                    "Current time: {}, Slot start time: {}, Submit start time: {}",
                    time::OffsetDateTime::now_utc().unix_timestamp_nanos(),
                    slot_start_timestamp,
                    submit_start_time
                );
                info!("Sleep duration: {}", sleep_duration / 1_000_000_000);
                if sleep_duration.is_positive() {
                    info!("Sleeping for {} s until slot {} starts", sleep_duration, slot + 1);
                    tokio::time::sleep(Duration::from_nanos(
                        sleep_duration.try_into().expect("positive sleep duration"),
                    ))
                    .await;
                } else {
                    warn!("slot is in past, skipping");
                    continue;
                }

                // get all the preconf requests from the ready pool
                let preconf_requests = self.preconf_requests()?;

                if preconf_requests.is_empty() {
                    last_slot = slot;
                    continue;
                } else {
                    let signed_constraints_message = preconf_reqs_to_constraints(
                        preconf_requests,
                        &self.bls_sk,
                        &self.context,
                        slot + 1,
                    )
                    .await?;
                    let max_retries = 5;
                    let mut i = 0;

                    'submit: while let Err(e) = constraint_client
                        .send_set_constraints(
                            signed_constraints_message.clone(),
                            slot_start_timestamp,
                        )
                        .await
                    {
                        error!(err = ?e, "Error submitting constraints to relay, retrying...");
                        i += 1;
                        if i >= max_retries {
                            error!("Max retries reached while submitting to relay");
                            break 'submit;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }

                last_slot = slot;
            }
            Ok(())
        }
    }

    /// Expected forms
    ///     - PreconfRequest without PreconfTx
    ///     - PreconfRequest with PreconfTx
    pub async fn request_preconf(
        &self,
        preconf_request: PreconfRequest,
    ) -> Result<PreconfResponse, RpcError> {
        // TODO: check for sender's collateral
        // A sender must have enough collateral to cover for the penalty imposed by the preconfer on
        // the sender if the sender fails to submit the preconf_tx

        let request_id = Uuid::new_v4();

        match self.preconf_pool.request_inclusion(preconf_request.clone(), request_id).await {
            Ok(PoolType::Ready) | Ok(PoolType::Pending) => {
                let message_digest = {
                    let mut data = Vec::new();
                    // First field is the concatenation of the transaction hash
                    data.extend_from_slice(
                        preconf_request
                            .transaction
                            .expect("preconf tx not found")
                            .tx_hash()
                            .as_slice(),
                    );

                    // Second field is the little endian encoding of the target slot
                    data.extend_from_slice(&preconf_request.target_slot.to_le_bytes());
                    keccak256(data)
                };
                let commitment =
                    self.ecdsa_signer.sign_hash(&message_digest).await.map_err(|e| {
                        RpcError::SignatureError(format!(
                            "Failed to sign inclusion commitment: {e:?}"
                        ))
                    })?;
                Ok(PreconfResponse::success(request_id, Some(commitment)))
            }
            Ok(PoolType::Parked) => Ok(PreconfResponse::success(request_id, None)),
            Err(e) => Err(RpcError::PoolError(e)),
        }
    }

    pub async fn cancel_preconf_request(
        &self,
        _cancel_preconf_request: CancelPreconfRequest,
    ) -> Result<CancelPreconfResponse, PoolError> {
        unimplemented!()
    }

    pub async fn preconf_transaction(
        &self,
        request_id: Uuid,
        transaction: TxEnvelope,
    ) -> Result<PreconfResponse, RpcError> {
        let mut preconf_request = self
            .preconf_pool
            .get_parked(request_id)
            .ok_or(PoolError::PreconfRequestNotFound(request_id))?;
        if preconf_request.transaction.is_some() {
            return Err(RpcError::PreconfTxAlreadySet);
        }
        preconf_request.transaction = Some(transaction.clone());

        match self.preconf_pool.request_inclusion(preconf_request.clone(), request_id).await {
            Ok(PoolType::Ready) | Ok(PoolType::Pending) => {
                let message_digest = {
                    let mut data = Vec::new();
                    // First field is the concatenation of the transaction hash
                    data.extend_from_slice(
                        preconf_request
                            .transaction
                            .expect("preconf tx not found")
                            .tx_hash()
                            .as_slice(),
                    );

                    // Second field is the little endian encoding of the target slot
                    data.extend_from_slice(&preconf_request.target_slot.to_le_bytes());
                    keccak256(data)
                };
                let commitment =
                    self.ecdsa_signer.sign_hash(&message_digest).await.map_err(|e| {
                        RpcError::SignatureError(format!(
                            "Failed to sign inclusion commitment: {e:?}"
                        ))
                    })?;
                Ok(PreconfResponse::success(request_id, Some(commitment)))
            }
            Err(PoolError::InvalidPreconfTx(_)) => {
                self.preconf_pool.delete_parked(request_id);
                // TODO penalize the sender
                // self.preconfer.taiyi_core_contract.exhaust(preconf_request.into()).call().await?;
                Err(RpcError::PreconfRequestError("Invalid preconf tx".to_string()))
            }
            _ => Err(RpcError::UnknownError("Invalid pool state".to_string())),
        }
    }

    pub async fn check_preconf_request_status(
        &self,
        request_id: Uuid,
    ) -> Result<PreconfStatusResponse, PoolError> {
        let pool = self.preconf_pool.get_pool(request_id)?;
        let status = match pool {
            PoolType::Parked => PreconfStatus::Pending,
            PoolType::Pending => PreconfStatus::Pending,
            PoolType::Ready => PreconfStatus::Accepted,
        };
        Ok(PreconfStatusResponse { status })
    }

    pub async fn get_slots(&self) -> Result<Vec<u64>, RpcError> {
        let current_slot = self.network_state.get_current_slot();
        let available_slots = self
            .network_state
            .get_proposer_duties()
            .iter()
            .map(|duty| duty.slot)
            .filter(|slot| *slot > current_slot)
            .collect();
        Ok(available_slots)
    }
}
